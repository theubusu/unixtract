mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::formats::funai_upg::funai_des::funai_des_decrypt;
use include::*;
use crate::keys;

pub struct FunaiBdpContext {
    key: u32,
}

pub fn is_funai_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 16)?;

    for key_hex in keys::FUNAI_BDP {
        let key_bytes = hex::decode(key_hex)?;
        let key_u32 = u32::from_le_bytes(key_bytes.as_slice().try_into()?);
        let decrypted = funai_des_decrypt(&header, key_u32);

        if decrypted == b"index_table\x00\x00\x00\x00\x00"{
            return Ok(Some(Box::new(FunaiBdpContext {key: key_u32})))
        }
    }

    Ok(None)
}

pub fn extract_funai_bdp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<FunaiBdpContext>().expect("Missing context");

    let mut data = Vec::new(); //to decrypt entire file
    file.read_to_end(&mut data)?;

    println!("Decrypting file...");
    data = funai_des_decrypt(&data, ctx.key);
    let mut file_reader = Cursor::new(data);

    file_reader.seek(SeekFrom::Start(0x20))?;

    let index_entry_count: u32 = file_reader.read_le()?;
    let mut entries: Vec<IndexTableEntry> = Vec::new();

    for _i in 0..index_entry_count {
        let entry: IndexTableEntry = file_reader.read_le()?;
        entries.push(entry);
    }

    for (i, entry) in entries.iter().enumerate() {
        println!("\n({}/{}) - {}, Offset: {}, Size: {}", i +1, index_entry_count, entry.name(), entry.offset, entry.size);
        
        file_reader.seek(SeekFrom::Start(entry.offset as u64))?;
        let data = common::read_exact(&mut file_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.name()));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

        //at start of location there is an additional 0x20 with the entry's name
        out_file.write_all(&data[0x20..])?;

        println!("-- Saved file!");
    }

    Ok(())
}
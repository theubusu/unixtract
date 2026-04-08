mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common::{self, read_exact};
use crate::formats::funai_upg::funai_des::funai_des_decrypt;
use include::*;
use crate::keys;
use crate::utils::compression::decompress_zlib;

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
        let mut data = common::read_exact(&mut file_reader, entry.size as usize)?;

        if is_cmpr(&data, entry.size) {
            println!("- cmpr detected!, 'uncompressing' data...");
            data = uncmpr_data(&data)?;

        } else if entry.name().ends_with("_image_rom") {
            println!("- Decompressing image ROM...");
            data = uncomp_image_rom(&data)?;

        } else {//strip partition name at start
            data = data[0x20..].to_vec()
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.name()));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

        out_file.write_all(&data)?;

        println!("-- Saved file!");
    }

    Ok(())
}

pub fn uncmpr_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_reader = Cursor::new(data);
    let _part_name = read_exact(&mut data_reader, 0x20)?;
    let cmpr_header: CmprHeader = data_reader.read_le()?;
    println!("[cmpr] out chk: {:02x}, count: {}, data size: {}",
            cmpr_header.out_checksum, cmpr_header.count, cmpr_header.data_size);

    let mut out_data: Vec<u8> = Vec::new();

    for (i, entry) in cmpr_header.entries.iter().enumerate() {
        println!("[cmpr] ({}/{}) size: {}, mode: {}, fill: {:02x}",
                i+1, cmpr_header.count, entry.size, entry.mode, entry.fill);

        let mut data;
        if entry.mode == 0 { //raw data
            data = read_exact(&mut data_reader, entry.size as usize)?;

        } else if entry.mode == 1 { //fill data
            data = vec![entry.fill as u8; entry.size as usize];

        } else {
            return Err("invalid/unknown entry mode value!".into());
        };

        out_data.append(&mut data);
    }

    Ok(out_data)
}

pub fn uncomp_image_rom(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_reader = Cursor::new(data);
    let _part_name = read_exact(&mut data_reader, 0x20)?;
    let header: ImageRomHeader = data_reader.read_le()?;
    println!("[rom] count: {}", header.count);

    let mut out_data: Vec<u8> = Vec::new();

    for (i, entry) in header.entries.iter().enumerate() {
        let offset = header.start_offset + entry.offset;

        println!("[rom] ({}/{}) offset: {}, size: {}",
                i+1, header.count, offset, entry.size);

        data_reader.seek(SeekFrom::Start(offset as u64))?;
        let compr_data = read_exact(&mut data_reader, entry.size as usize)?;

        println!("[rom] - Decompressing...");
        let mut decomp_data = decompress_zlib(&compr_data)?;

        out_data.append(&mut decomp_data);
    }

    Ok(out_data)
}
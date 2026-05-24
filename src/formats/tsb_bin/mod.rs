mod include;
mod tsb_des;
use std::any::Any;
use crate::AppContext;
use crate::utils::compression::decompress_zlib;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;
use tsb_des::decrypt;

struct TsbBinCtx {
    key: Option<[u8; 8]>
}

pub fn is_tsb_bin_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 256)?;
    if is_valid_header_checksum(&header) {
        return Ok(Some(Box::new(TsbBinCtx {key: None})));
    }

    // -- failed, try with decrypt
    //derive key from FILE SIZE (yes)
    let file_size = file.metadata()?.len() as u32;
    let mut key = [0u8; 8];
    key[..4].copy_from_slice(&file_size.to_le_bytes());
    let inv = !file_size;
    key[4..].copy_from_slice(&inv.to_le_bytes());

    let dec_header = decrypt(&header, &key);
    if is_valid_header_checksum(&dec_header) {
        Ok(Some(Box::new(TsbBinCtx {key: Some(key)})))
    } else {
        Ok(None)
    }
}

pub fn extract_tsb_bin(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<TsbBinCtx>().expect("Missing context");

    let mut header = common::read_file(&mut file, 0, 0x400)?;
    if let Some(key) = ctx.key {    //decrypt header
        println!("File is encrypted, using key: {}", hex::encode(&key));
        header = decrypt(&header, &key);
        opt_dump_dec_hdr(app_ctx, &header, "header")?;
    }

    let mut hdr_rdr = Cursor::new(header);
    let hdr: Header = hdr_rdr.read_be()?;

    println!("File info -\nSize: {}\nEntry count: {}\nBuild no.: {}\nEntry address: 0x{:02x}"
            ,hdr.lenght, hdr.entry_count, hdr.build_no(), hdr.entry_addr);

    for (i, entry) in hdr.entries.iter().enumerate() {
        println!("\n({}/{}) - {}, Size: {}, Offset: {}, Load address: 0x{:02x}",
                i+1, hdr.entry_count, entry.name(), entry.size, entry.offset, entry.load_addr);
        
        let mut data;
        if let Some(key) = ctx.key {
            let enc_data = common::read_file(&mut file, entry.offset as u64, (entry.size as usize + 7) & !7)?;  //read aligned to 8b blocks for decryption
            println!("- Decrypting...");
            data = decrypt(&enc_data, &key);
            data.truncate(entry.size as usize); //discard alignment

        } else {
            data = common::read_file(&mut file, entry.offset as u64, entry.size as usize)?;
        }

        if entry.is_compressed() {
            println!("- Decompressing...");
            data = decompress_zlib(&data)?;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.name()));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");
    }

    Ok(())
}
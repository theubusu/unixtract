mod include;
use std::any::Any;
use crate::{InputTarget, AppContext};

use std::fs::File;
use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::formats;
use include::*;

pub fn is_sony_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"\x01\x73\xEC\xC9" || header == b"\x01\x73\xEC\x1F" || header == b"\xEC\x7D\xB0\xB0" { //MSB1x, MSB0x, BDPPxx
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_sony_bdp(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let obf_header = common::read_exact(&mut file, 300)?;
    let header = hex_substitute(&obf_header);
    let mut hdr_reader = Cursor::new(header);
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFirmware: {}\nVersion: {}\nDate: {}\nFile size: {}", 
            hdr.firmware_name(), hdr.firmware_version(), hdr.date(), hdr.file_size);

    let mut last_file_path: Option<PathBuf> = None;
    let mut first_entry_offset = 0;
    let mut i = 1;
    loop {
        if (i != 1) && (hdr_reader.position() >= first_entry_offset) {
            break
        }

        let entry: Entry = hdr_reader.read_le()?;
        if entry.size == 0 {
            continue
        }

        println!("\n#{} - Offset: {}, Size: {}", i, entry.offset, entry.size);
        if i == 1 {
            first_entry_offset = entry.offset as u64;
        }

        let obf_data = common::read_file(&file, entry.offset as u64, entry.size as usize)?;
        let data = hex_substitute(&obf_data);

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i));
        last_file_path = Some(output_path.clone());

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;          
        out_file.write_all(&data)?;

        println!("- Saved file!");
        i += 1;
    }

    //The last file is often a Mtk BDP file so we can extract that here.
    if last_file_path.is_some() {
        println!("\nChecking if it's also MTK BDP...");

        let last_file = File::open(last_file_path.unwrap())?;
        let mtk_extraction_path = app_ctx.output_dir.join(format!("{}", i + 1));

        //this is getting stupid...
        let ctx: AppContext = AppContext { input: InputTarget::File(last_file), output_dir: mtk_extraction_path, options: app_ctx.options.clone() };

        if let Some(result) = formats::mtk_bdp::is_mtk_bdp_file(&ctx)? {
            println!("- MTK BDP file detected!\n");
            
            formats::mtk_bdp::extract_mtk_bdp(&ctx, result)?;
        } else {
            println!("- Not an MTK BDP file.");    
        }
    }
     
    Ok(())
}
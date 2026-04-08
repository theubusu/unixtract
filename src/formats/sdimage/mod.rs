mod include;
use std::any::Any;
use std::fs::{self, OpenOptions};
use std::io::{Seek, Write};
use std::path::Path;
use crate::AppContext;
use binrw::BinReaderExt;

use include::*;
use crate::utils::common;

pub fn is_sdimage_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 8)?;
    if header == b"PFUS01US" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_sdimage(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    file.seek(std::io::SeekFrom::Start(16))?;

    let mut e_i = 0;
    while file.stream_position()? < file.metadata()?.len() as u64 {
        let entry: EntryHeader = file.read_le()?;
        println!("\n#{} - {} ({}), Size: {}, Version: {}.{}.{}.{}, Model ID: {}, Info: {}{} {}", 
                e_i+1, entry.target_name(), entry.target_id, entry.size1, entry.version[3], entry.version[2], entry.version[1], entry.version[0], entry.model_id, entry.info(),
                if entry.is_encrypted() {" [ENCRYPTED]"} else {""}, if entry.is_empty() {"[EMPTY]"} else {""});

        if !entry.is_empty() {
            let info = entry.info();
            let filename = info.split("FN=\"").nth(1).and_then(|s| s.split('"').next()).unwrap();
            println!("- Filename: {}", filename);

            let data = common::read_exact(&mut file, entry.size1 as usize)?;

            fs::create_dir_all(&app_ctx.output_dir)?;
            let out_folder = Path::new(&app_ctx.output_dir).join(entry.target_name());
            fs::create_dir_all(&out_folder)?;
            let output_path = out_folder.join(filename);

            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            out_file.write_all(&data)?;

            println!("-- Saved file!");
        }

        e_i += 1;
    }

    Ok(())
}
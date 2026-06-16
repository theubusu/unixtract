mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_novatek_bin_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let entry_magic = common::read_file(&file, 0, 8)?;
    let size_str = common::read_file(&file, 8, 8)?; 
    if entry_magic == ENTRY_MAGIC && size_str.is_ascii(){
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_novatek_bin(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let file_size = file.metadata()?.len();

    let mut e_i = 0;
    while file.stream_position()? < file_size {
        let entry: Entry = file.read_le()?;
        if &entry.magic != ENTRY_MAGIC {
            return Err(format!("invalid entry magic at {}", file.stream_position()?).into())
        }

        println!("\n#{} - {}, Size: {}", e_i+1, entry.name(), entry.size());

        let data = common::read_exact(&mut file, entry.size())?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.name()));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");

        e_i += 1;
    }

    Ok(())
}
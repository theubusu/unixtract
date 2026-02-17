mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_funai_upg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 6)?;
    if header == b"UPG\x00\x00\x00" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_funai_upg(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    println!("File info:\nFile size: {}\nEntry count: {}", header.file_size, header.entry_count);

    for i in 0..header.entry_count {
        let entry: Entry = file.read_le()?;
        println!("\n({}/{}) - Type: {}, Size: {}", i + 1, header.entry_count, entry.entry_type, entry.entry_size);

        let data = common::read_exact(&mut file, entry.entry_size as usize - 2 - 4)?; //size has the unk field + crc32 at the end
        let _crc32 = common::read_exact(&mut file, 4)?; //btw the CRC32 includes the entry header

        if entry.entry_type == 0 {
            let entry_string = common::string_from_bytes(&data);
            println!("Descriptor entry info:\n{}", entry_string);
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", i + 1, entry.entry_type));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }
    
    Ok(())
}
mod include;
use std::any::Any;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use crate::AppContext;

use crate::utils::common;
use binrw::BinReaderExt;
use include::*;

pub fn is_gx_dvb_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let table_magic = common::read_file(&file, TABLE_OFFSET, 4)?;
    if table_magic == b"\xAA\xBC\xDE\xFA" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_gx_dvb(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;    

    file.seek(SeekFrom::Start(TABLE_OFFSET))?;
    let table: PartTable = file.read_be()?;

    println!("Part count: {}", table.part_count);

    for (i, part) in table.part_entries.iter().enumerate() {
        println!("\n({}/{}) - {}, Offset: {}, Total size: {}, Used size: {}",
                i+1, table.part_count, part.name(), part.start, part.total_size, part.used_size);

        let data = common::read_file(&file, part.start as u64, part.total_size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", part.name()));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;        
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
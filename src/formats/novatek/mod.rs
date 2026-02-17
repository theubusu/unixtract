mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_novatek_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"NFWB" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_novatek(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    println!("File info:\nFirmware name: {}\nVersion: {}.{}\nData size: {}\nPart count: {}",
            header.firmware_name(), header.version_major, header.version_minor, header.data_size, header.part_count);

    let mut entries: Vec<PartEntry> = Vec::new();
    for _i in 0..header.part_count {
        let part: PartEntry = file.read_le()?;
        entries.push(part);
    }

    let mut e_i = 0;
    for entry in &entries {
        e_i += 1;
        println!("\n({}/{}) - ID: {}, Offset: {}, Size: {}", e_i, entries.len(), entry.id, entry.offset, entry.size);

        let data = common::read_file(&file, entry.offset as u64, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", e_i, entry.id));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;       
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
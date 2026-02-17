mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_slp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"SLP\x00" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_slp(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    println!("File info:\nModel: {}\nVersion: {}\nFirmware: {}\nNew type: {}\n",
            header.model(), header.version(), header.firmware(), header.is_new_type());

    let mut first_entry_offset = 0;
    let mut entries: Vec<EntryOld> = Vec::new();

    for i in 0..100 {
        if (i != 0) && (file.stream_position()? >= first_entry_offset) {
            break
        }
        let offset;
        let size;
        if header.is_new_type() {
            let entry: EntryNew = file.read_le()?;
            offset = entry.offset;
            size = entry.size;
        } else {
            let entry: EntryOld = file.read_le()?;
            offset = entry.offset;
            size = entry.size;
        }
        if i == 0 {
            first_entry_offset = offset as u64;
        }
        println!("{}. Offset: {}, Size: {}", i + 1, offset, size);
        entries.push(EntryOld {size: size, _unk: 0, offset: offset, _unk2: 0});
    }

    let mut i = 1;
    for entry in &entries {
        println!("\n({}/{}) - Offset: {}, Size: {}", i, &entries.len(), entry.offset, entry.size);
        file.seek(SeekFrom::Start(entry.offset.into()))?;
        let data = common::read_exact(&mut file, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");

        i += 1;
    }

    println!("\nExtraction finished!");

    Ok(())
}
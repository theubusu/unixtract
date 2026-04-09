mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_cd5_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let hdr_magic = common::read_file(&file, 15, 8)?;
    if hdr_magic == b"20 10001" { //not sure about it but fine for samsung and telestar
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_cd5(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let dwld_hdr_desc: DescriptorHeader = file.read_be()?;
    if dwld_hdr_desc.magic != 0x11 {
        return Err("Invalid download header magic!".into());
    }
    let mut dwld_hdr_reader = Cursor::new(common::read_exact(&mut file, dwld_hdr_desc.size as usize)?);
    let dwld_hdr: DownloadHeader = dwld_hdr_reader.read_be()?;

    // like Loader Data screen
    println!("File info -\nManufacturer code: {}\nHardware Version: {}\nVersion(DSN): {}(0x{:02x})\nVariant/Sub-variant: 0x{:02x}/0x{:02x}\nModule count: {}",
            dwld_hdr.manufacturer_code, dwld_hdr.hardware_version, dwld_hdr.version, dwld_hdr.version, dwld_hdr.variant, dwld_hdr.sub_variant, dwld_hdr.module_count);

    for (i, module) in dwld_hdr.module_entries.iter().enumerate() {
        let mod_hdr_desc: DescriptorHeader = file.read_be()?;
        if mod_hdr_desc.magic != 0x22 {
            return Err("Invalid module download header magic!".into());
        }
        let mut mod_hdr_reader = Cursor::new(common::read_exact(&mut file, mod_hdr_desc.size as usize)?);
        let mod_hdr: ModuleDownloadHeader = mod_hdr_reader.read_be()?;
        if mod_hdr.module_id != module.module_id {
            return Err("Module id mismatch in download header and module header!".into());
        }

        println!("\n({}/{}) Module {}(0x{:02x}) - Version(DSN): {}(0x{:02x}), Size: {}, Segment size: {}, Segment count: {} {}",
                i+1, dwld_hdr.module_count, mod_hdr.module_id, mod_hdr.module_id, module.version, module.version, mod_hdr.out_size, mod_hdr.segment_size, mod_hdr.segment_count,
                if mod_hdr.is_encrypted() {"[ENCRYPTED]"} else {""});

        let mut module_data: Vec<u8> = Vec::new();

        for s_i in 0..mod_hdr.segment_count {
            let mut segment: DownloadSegment = file.read_be()?;
            if segment.magic != 0x33 {
                return Err("Invalid segment magic!".into());
            }
            if segment.module_id != mod_hdr.module_id {
                return Err("Module id mismatch in segment and module header!".into());
            }

            println!("  Segment {}/{} - Size: {}", s_i+1, mod_hdr.segment_count, segment.data_size);
            module_data.append(&mut segment.data);
        }

        let out_data;
        if mod_hdr.is_encrypted() {
            println!("- Warning: data is encrypted, so cannot read inner header - saving ENCRYPTED data!");
            out_data = module_data;
        }
        else {
            let mut mod_data_rdr = Cursor::new(module_data);
            let inner_mod_hdr: InnerModuleHeader = mod_data_rdr.read_be()?;
            println!("- Inner header size: {}, Data size: {}", inner_mod_hdr.header_size, inner_mod_hdr.data_size);
            mod_data_rdr.seek(SeekFrom::Start(inner_mod_hdr.header_size as u64))?;
            out_data = common::read_exact(&mut mod_data_rdr, inner_mod_hdr.data_size as usize)?;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", mod_hdr.module_id));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;        
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");

    }

    Ok(())
}
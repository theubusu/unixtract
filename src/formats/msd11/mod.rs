mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::io::Write;
use binrw::BinReaderExt;

use crate::utils::common;
use crate::keys;
use crate::formats::msd::{decrypt_aes_salted_tizen, decrypt_aes_tizen};
use crate::formats::msd::msd_ouith_parser_tizen_1_9::{parse_blob_1_9};
use include::*;

pub fn is_msd11_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 6)?;
    if header == b"MSDU11" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_msd11(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let print_ouith_tree = app_ctx.options.iter().any(|e| e == "msd:print_ouith");

    let header: FileHeader = file.read_le()?;
    println!("\nNumber of sections: {}", header.section_count);

    let mut sections: Vec<SectionEntry> = Vec::new();
    for _i in 0..header.section_count {
        let section: SectionEntry = file.read_le()?;
        println!("Section {}: offset: {}, size: {}", section.index, section.offset, section.size);
        sections.push(section);
    }

    let header_count: u32 = file.read_le()?;
    println!("\nNumber of headers: {}", header_count);

    let mut headers: Vec<HeaderEntry> = Vec::new();
    for i in 0..header_count {
        let header: HeaderEntry = file.read_le()?;
        println!("Header {}: {}, offset: {}, size: {}", i + 1, header.name(), header.offset, header.size);
        headers.push(header);
    }

    //use first header
    let firmware_name = &headers[0].name();
    println!("\nFirmware name: {}", firmware_name);

    let mut passphrase: Option<&str> = None;
    let passphrase_bytes;

    //find passphrase
    for (prefix, value) in keys::MSD11 {
        if firmware_name.starts_with(prefix) {
            passphrase = Some(value);
            break;
        }
    }
    if let Some(p) = passphrase {
        println!("Passphrase: {}", p);
        passphrase_bytes = hex::decode(p)?;
    } else {
        return Err("This firmware is not supported!".into());
    }

    let toc_offset = headers[0].offset + 8;
    let toc_size = headers[0].size - 8;
    let toc_data = common::read_file(&file, toc_offset as u64, toc_size as usize)?;

    let toc = decrypt_aes_salted_tizen(&toc_data, &passphrase_bytes)?;
    let (items, info) = parse_blob_1_9(&toc, print_ouith_tree)?;

    if let Some(info) = info {
        println!("\nImage info:\n{} {}.{}",
                info.name(), info.major_ver, info.minor_ver);
    }

    for (i, item) in items.iter().enumerate() {
        let size = sections[i as usize].size;
        let offset = sections[i as usize].offset;

        println!("\n({}/{}) - {}, Size: {}",
                i + 1, items.len(), item.name, size);

        if sections[i as usize].index != item.item_id {
            return Err("Item ID in TOC does not match ID from header!".into());
        }

        let stored_data = common::read_file(&file, offset as u64, size as usize)?;

        let out_data;
        if item.aes_encryption {
            println!("- Decrypting...");
            let salt = item.aes_salt.as_ref().ok_or("AES salt missing!")?;
            out_data = decrypt_aes_tizen(&stored_data, &passphrase_bytes, salt)?;
        } else {
            out_data = stored_data;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(item.name.clone());
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;   
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");
    }

    Ok(())
}
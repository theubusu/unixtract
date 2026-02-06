use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "msd10", detector_func: is_msd10_file, extractor_func: extract_msd10 }
}

use std::fs::{self, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::msd::{decrypt_aes_salted_old, decrypt_aes_salted_tizen, decrypt_aes_tizen};
use crate::utils::msd_ouith_parser_old::{parse_ouith_blob};
use crate::utils::msd_ouith_parser_tizen_1_8::{parse_blob_1_8};

#[derive(BinRead)]
struct FileHeader {
    #[br(count = 6)] _magic_bytes: Vec<u8>,
    section_count: u32
}

#[derive(BinRead)]
struct SectionEntry {
    index: u32,
    offset: u32,
    size: u32,
}

#[derive(BinRead)]
struct HeaderEntry {
    offset: u32,
    size: u32,
    _name_length: u8,
    #[br(count = _name_length)] name_bytes: Vec<u8>,
}
impl HeaderEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

struct Section {
    index: u32,
    offset: u32,
    size: u32,
}

pub fn is_msd10_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 6)?;
    if header == b"MSDU10" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_msd10(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: FileHeader = file.read_le()?;
    println!("\nNumber of sections: {}", header.section_count);

    let mut sections: Vec<Section> = Vec::new();
    for _i in 0..header.section_count {
        let section: SectionEntry = file.read_le()?;
        println!("Section {}: offset: {}, size: {}", section.index, section.offset, section.size);
        sections.push(Section {index: section.index, offset: section.offset, size: section.size});
    }

    let _zero_padding = common::read_exact(&mut file, 4)?;
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
    let mut firmware_type = "";
    let passphrase_bytes;

    //find passphrase
    for (prefix, fw_type, value) in keys::MSD10 {
        if firmware_name.starts_with(prefix) {
            passphrase = Some(value);
            firmware_type = fw_type;
            break;
        }
    }
    if let Some(p) = passphrase {
        println!("Passphrase: {}", p);
        passphrase_bytes = hex::decode(p)?;
        println!("Firmware type: {}", firmware_type);
    } else {
        println!("Sorry, this firmware is not supported!");
        std::process::exit(1);
    }

    let toc_offset = headers[0].offset;
    let toc_size = headers[0].size;
    let toc_data = common::read_file(&file, toc_offset as u64, toc_size as usize)?;

    //parse TOC
    if firmware_type == "tizen" {
        let toc = decrypt_aes_salted_tizen(&toc_data, &passphrase_bytes)?;
        let (items, info) = parse_blob_1_8(&toc)?;

        if let Some(info) = info {
            println!("\nImage info:\n{} {}.{} {}/{}/{}",
                    info.name(), info.major_ver, info.minor_ver, info.date_day, info.date_month, info.date_year);
        }

        for (i, item) in items.iter().enumerate() {
            let size = sections[i as usize].size;
            let offset = sections[i as usize].offset;

            println!("\n({}/{}) - {}, Size: {}",
                    i + 1, items.len(), item.name, size);

            assert!(sections[i as usize].index == item.item_id, "Item ID in TOC does not match ID from header!");

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

    } else if firmware_type == "old" {
        let toc = decrypt_aes_salted_old(&toc_data, &passphrase_bytes)?;
        let (items, info) = parse_ouith_blob(&toc)?;

        if let Some(info) = info {
            println!("\nImage info:\n{} {}.{} {}/{}/20{}",
                    info.name(), info.major_ver, info.minor_ver, info.date_day, info.date_month, info.date_year);
        }

        for (i, item) in items.iter().enumerate() {
            let offset = sections[i as usize].offset;
            let type_str = if item.item_type == 0x0A {"Partition"} else if item.item_type == 0x0B {"File"} else if item.item_type == 0x11 {"CMAC Data"} else {"Unknown"};
            println!("\n({}/{}) - {}, Type: {}, Size: {}",
                    item.item_id, items.len(), item.name, type_str, item.all_size);

            assert!(sections[i as usize].index == item.item_id, "Item ID in TOC does not match ID from header!");

            if item.item_type == 0x11 { //Skip CMAC DATA
                println!("- Skipping CMAC Data...");
                continue
            }
            
            file.seek(SeekFrom::Start(offset as u64))?;

            //skip heading metadata thing
            file.seek(SeekFrom::Current(item.heading_size as i64))?;
    
            let stored_data = common::read_exact(&mut file, item.data_size as usize)?;
            let out_data;
            if item.aes_encryption {
                println!("- Decrypting...");
                out_data = decrypt_aes_salted_old(&stored_data, &passphrase_bytes)?;
            } else {
                out_data = stored_data;
            }

            let output_path = Path::new(&app_ctx.output_dir).join(item.name.clone());
            fs::create_dir_all(&app_ctx.output_dir)?;
            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            out_file.write_all(&out_data)?;

            println!("-- Saved file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
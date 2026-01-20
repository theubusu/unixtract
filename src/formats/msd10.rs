use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Cursor, Write, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::msd::{decrypt_aes_salted_old, decrypt_aes_salted_tizen, decrypt_aes_tizen};
use crate::utils::msd_ouith_parser_old::{parse_ouith_blob};

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

#[derive(BinRead)]
struct TizenTocEntry {
    #[br(count = 44)] _unk1: Vec<u8>,
    _name_length: u8,
    #[br(count = _name_length)] name_bytes: Vec<u8>,
    #[br(count = 314)] _unk2: Vec<u8>,
    #[br(count = 8)] salt: Vec<u8>,
    #[br(count = 13)] _unk3: Vec<u8>,
}
impl TizenTocEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

pub fn is_msd10_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 6).expect("Failed to read from file.");
    if header == b"MSDU10" {
        true
    } else {
        false
    }
}

pub fn extract_msd10(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
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
        let mut toc_reader = Cursor::new(toc);

        toc_reader.seek(SeekFrom::Current(256))?; // probably signature
        toc_reader.seek(SeekFrom::Current(50))?; // Tizen Software Upgrade Tree Binary Format ver. 1.8

        for i in 0..header.section_count {
            let entry: TizenTocEntry = toc_reader.read_le()?;
            let offset = sections[i as usize].offset;
            let size = sections[i as usize].size;

            println!("\n({}/{}) - {}, Size: {}", sections[i as usize].index, sections.len(), entry.name(), size);

            let encrypted_data = common::read_file(&file, offset as u64, size as usize)?;

            println!("- Decrypting...");
            let decrypted_data = decrypt_aes_tizen(&encrypted_data, &passphrase_bytes, &entry.salt)?;

            let output_path = Path::new(&output_folder).join(entry.name());
            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(output_path)?;
            
            out_file.write_all(&decrypted_data)?;

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
            let type_str = if item.item_type == 0x0A {"Partition"} else if item.item_type == 0x0B {"File"} else if item.item_type == 0x11 {"CMAC Data"} else {"Unknown"};
            println!("\n({}/{}) - {}, Type: {}, Size: {}",
                    item.item_id, items.len(), item.name, type_str, item.all_size);

            assert!(sections[i as usize].index == item.item_id, "Item ID in TOC does not match ID from header!");

            if item.item_type == 0x11 { //Skip CMAC DATA
                println!("- Skipping CMAC Data...");
                continue
            }
            
            let offset = sections[i as usize].offset;
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

            let output_path = Path::new(&output_folder).join(item.name.clone());
            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(output_path)?;
         
            out_file.write_all(&out_data)?;

            println!("-- Saved file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
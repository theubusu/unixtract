use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::msd::{decrypt_aes_salted_tizen, decrypt_aes_tizen};
use crate::utils::msd_ouith_parser_tizen_1_9::{parse_blob_1_9};

#[derive(BinRead)]
struct FileHeader {
    #[br(count = 6)] _magic_bytes: Vec<u8>,
    _header_checksum: u32, //CRC32 of data with the size of "_header_size"
    _header_size: u64,
    section_count: u32,
}

#[derive(BinRead)]
struct SectionEntry {
    index: u32,
    offset: u64,
    size: u64,
}

#[derive(BinRead)]
struct HeaderEntry {
    offset: u64,
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
    offset: u64,
    size: u64,
}

pub fn is_msd11_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 6).expect("Failed to read from file.");
    if header == b"MSDU11" {
        true
    } else {
        false
    }
}

pub fn extract_msd11(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let header: FileHeader = file.read_le()?;
    println!("\nNumber of sections: {}", header.section_count);

    let mut sections: Vec<Section> = Vec::new();
    for _i in 0..header.section_count {
        let section: SectionEntry = file.read_le()?;
        println!("Section {}: offset: {}, size: {}", section.index, section.offset, section.size);
        sections.push(Section {index: section.index, offset: section.offset, size: section.size});
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
        println!("Sorry, this firmware is not supported!");
        std::process::exit(1);
    }

    let toc_offset = headers[0].offset + 8;
    let toc_size = headers[0].size - 8;
    let toc_data = common::read_file(&file, toc_offset as u64, toc_size as usize)?;

    let toc = decrypt_aes_salted_tizen(&toc_data, &passphrase_bytes)?;
    let (items, info) = parse_blob_1_9(&toc)?;

    if let Some(info) = info {
        println!("\nImage info:\n{} {}.{}",
                info.name(), info.major_ver, info.minor_ver);
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

        let output_path = Path::new(&output_folder).join(item.name.clone());
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;   
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Cursor, Write, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::msd::{decrypt_aes_salted_old, decrypt_aes_salted_tizen, decrypt_aes_tizen};

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
    name: String,
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

#[derive(BinRead)]
struct OldTocEntry {
    #[br(count = 4)] _magic: Vec<u8>,
    segment_length: u32,
    segment_size: u32,
    #[br(count = 26)] _unk: Vec<u8>,
    name_lenght: u8,
    #[br(count = name_lenght)] name_bytes: Vec<u8>,
}
impl OldTocEntry {
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
        sections.push(Section {index: section.index, offset: section.offset, size: section.size, name: "".to_owned()});
    }

    let _0 = common::read_exact(&mut file, 4)?; //0000
    let header_count_bytes = common::read_exact(&mut file, 4)?;
    let header_count = u32::from_le_bytes(header_count_bytes.try_into().unwrap());
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

            println!("\nSection {}: {}", sections[i as usize].index, entry.name());

            let offset = sections[i as usize].offset;
            let size = sections[i as usize].size;
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
        let mut toc_reader = Cursor::new(toc);

        toc_reader.seek(SeekFrom::Current(124))?; //probably signature + first magic

        for i in 0..header.section_count {            
            let entry: OldTocEntry = toc_reader.read_be()?;

            toc_reader.seek(SeekFrom::Current((entry.segment_length - entry.name_lenght as u32 - 31).into()))?;

            assert!(entry.segment_size == sections[i as usize].size, "size in TOC does not match size from header!");
            sections[i as usize].name = entry.name().clone();

            println!("\nSection {}: {}", sections[i as usize].index, entry.name());
            
            let offset = sections[i as usize].offset;
            let size = sections[i as usize].size;

            if i != 0 && entry.name() == sections[i as usize - 1].name { //second section with the same name is some sort of signature
                println!("- Skipping signature file...");
                continue;
            }
            
            let encrypted_data = common::read_file(&file, offset as u64 + 136, size as usize - 136)?;

            println!("- Decrypting...");
            let out_data = decrypt_aes_salted_old(&encrypted_data, &passphrase_bytes)?; 

            let output_path = Path::new(&output_folder).join(entry.name());
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
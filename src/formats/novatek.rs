use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write};

use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    #[br(count = 4)] _flags: Vec<u8>,
    _header_size: u32,
    _unused: u32,
    #[br(count = 16)] firmware_name_bytes: Vec<u8>,
    #[br(count = 20)] _unknown1: Vec<u8>,
    part_count: u32,
    _first_part_offset: u32,
    #[br(count = 116)] _unknown2: Vec<u8>,
}
impl Header {
    fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
}

#[derive(BinRead)]
struct PartEntry {
    #[br(count = 16)] _unknown: Vec<u8>,
    index: u32,
    size: u32,
    offset: u32,
}

pub fn is_novatek_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"NFWB" {
        true
    } else {
        false
    }
}

pub fn extract_novatek(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let header: Header = file.read_le()?;

    println!("File info:\nFirmware name: {}\nPart count: {}", header.firmware_name(), header.part_count);
    let mut entries: Vec<PartEntry> = Vec::new();

    for _i in 0..header.part_count {
        let part: PartEntry = file.read_le()?;
        entries.push(part);
    }

    let mut e_i = 0;
    for entry in &entries {
        e_i += 1;
        println!("\n({}/{}) - Index: {}, Offset: {}, Size: {}", e_i, entries.len(), entry.index, entry.offset, entry.size);

        let data = common::read_file(&file, entry.offset as u64, entry.size as usize)?;

        let output_path = Path::new(&output_folder).join(format!("{}.bin", e_i));

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
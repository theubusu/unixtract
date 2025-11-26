use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek};

use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    #[br(count = 4)] _flags: Vec<u8>,
    _header_size: u32,
    #[br(count = 40)] _unknown1: Vec<u8>,
    part_count: u32,
    _first_part_offset: u32,
    #[br(count = 116)] _unknown2: Vec<u8>,
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

    println!("\nPart count: {}", header.part_count);

    for i in 0..header.part_count {
        let part: PartEntry = file.read_le()?;

        let current_pos = file.stream_position()?;

        let data = common::read_file(&file, part.offset as u64, part.size as usize)?;

        println!("\nPart {}: index: {}, size: {}, offset: {}", i + 1, part.index, part.size, part.offset);

        let output_path = Path::new(&output_folder).join(format!("part_{}.bin", i + 1));

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");

        file.seek(std::io::SeekFrom::Start(current_pos))?;

    }

    Ok(())
}
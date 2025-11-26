use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

#[derive(BinRead)]
struct Header {
    #[br(count = 6)] _magic_bytes: Vec<u8>,
    entry_count: u16,
    file_size: u32,
}

#[derive(BinRead)]
struct Entry {
    entry_type: u16,
    entry_size: u32,
    _unk: u16,
}

pub fn is_funai_upg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 6).expect("Failed to read from file.");
    if header == b"UPG\x00\x00\x00" {
        true
    } else {
        false
    }
}

pub fn extract_funai_upg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let header: Header = file.read_le()?;
    println!("File info:\nFile size: {}\nEntry count: {}", header.file_size, header.entry_count);

    for i in 0..header.entry_count {
        let entry: Entry = file.read_le()?;
        println!("\nEntry {}/{} - Type: {}, Size: {}", i + 1, header.entry_count, entry.entry_type, entry.entry_size);

        let data = common::read_exact(&mut file, entry.entry_size as usize - 2 - 4)?; //size has the unk field + crc32 at the end
        let _crc32 = common::read_exact(&mut file, 4)?; //btw the CRC32 includes the entry header

        if entry.entry_type == 0 {
            let entry_string = common::string_from_bytes(&data);
            println!("Descriptor entry info:\n{}", entry_string);
        }

        let output_path = Path::new(&output_folder).join(format!("{}_{}.bin", i + 1, entry.entry_type));

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
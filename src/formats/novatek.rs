use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek};

use crate::common;

pub fn is_novatek_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    let header_string = String::from_utf8_lossy(&header);

    if header_string == "NFWB"{
        true
    } else {
        false
    }
}

pub fn extract_novatek(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _magic = common::read_exact(&mut file, 4)?; //NFWB magic
    let _flags = common::read_exact(&mut file, 4)?;
    let _header_size = common::read_exact(&mut file, 4)?;
    let _ = common::read_exact(&mut file, 40)?; //unknown

    let part_count_bytes = common::read_exact(&mut file, 4)?;
    let part_count = u32::from_le_bytes(part_count_bytes.try_into().unwrap());

    let _first_part_offset = common::read_exact(&mut file, 4)?;

    println!("Part count: {}", part_count);

    let _ = common::read_exact(&mut file, 116)?;

    for i in 0..part_count {
        let _ = common::read_exact(&mut file, 16)?; //unknown

        let index_bytes = common::read_exact(&mut file, 4)?;
        let index = u32::from_le_bytes(index_bytes.try_into().unwrap());

        let size_bytes = common::read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        let offset_bytes = common::read_exact(&mut file, 4)?;
        let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap());

        let current_pos = file.stream_position()?;

        let data = common::read_file(&file, offset as u64, size as usize)?;

        println!("- Part {}: index: {}, size: {}, offset: {}", i + 1, index, size, offset);

        let output_path = Path::new(&output_folder).join(format!("part_{}.bin", i + 1));

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("-- Saved file!");

        file.seek(std::io::SeekFrom::Start(current_pos))?;

    }

    Ok(())
}
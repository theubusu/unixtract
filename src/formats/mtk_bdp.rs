use std::fs::File;
use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Read, Write};
use binrw::{BinRead, BinReaderExt};

use crate::common;

#[derive(BinRead)]
struct TocEntry {
	id: u32,
    offset: u32,
    size: u32,
    _unk: u32,
    part_type: u32,
}

#[derive(BinRead)]
struct PartHeader {
	#[br(count = 20)] _unk1: Vec<u8>,
    part_count: u32,
    #[br(count = 40)] _unk2: Vec<u8>,
}

#[derive(BinRead)]
struct PartEntry {
	#[br(count = 16)] name_bytes: Vec<u8>,
    id: u32,
    _unk: u32,
    _part_type: u32,
    size: u32,
    #[br(count = 32)] _unknown: Vec<u8>,
}
impl PartEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

static ITIP_MAGIC: [u8; 8] = [0x69, 0x54, 0x49, 0x50, 0x69, 0x54, 0x49, 0x50];

fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|window| window == pattern)
}

pub fn is_mtk_bdp_file(mut file: &File) -> Option<usize> {
    let file_size = file.metadata().expect("REASON").len();
    let mut data = Vec::new();

    let start_offset = file_size.saturating_sub(file_size / 20); // only search in the last 5% of file (lets not waste time)
    let _ = file.seek(SeekFrom::Start(start_offset));

    file.read_to_end(&mut data).expect("Failed to read from file.");

    if let Some(pos) = find_bytes(&data, &ITIP_MAGIC) {
        Some(start_offset as usize + pos)
    } else {
        None
    }
}

pub fn extract_mtk_bdp(mut file: &File, output_folder: &str, offset_opt: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
    let offset = offset_opt.unwrap();
    println!("Reading PIT at: {}", offset);

    file.seek(SeekFrom::Start(offset as u64 + 8))?;

    let ittp_check = common::read_exact(&mut file, 8)?;
    let toc_offset;
    if ittp_check == ITIP_MAGIC {
        //old pit
        toc_offset = offset + 80;
    } else {
        //new pit
        let _ = common::read_exact(&mut file, 16)?;
        let toc_offset_bytes = common::read_exact(&mut file, 4)?;
        toc_offset = u32::from_le_bytes(toc_offset_bytes.try_into().unwrap()) as usize;
    }

    println!("\nReading TOC at: {}", toc_offset);
    file.seek(SeekFrom::Start(toc_offset as u64))?;

    let toc_check = common::read_exact(&mut file, 20)?;
    if toc_check != b"\xCD\xAB\x30\x85\xCD\xAB\x30\x85\xCD\xAB\x30\x85\xCD\xAB\x30\x85\xCD\xAB\x30\x85" {
        println!("Invalid TOC!");
        return Ok(())
    }

    let mut entries: Vec<TocEntry> = Vec::new();
    let mut part_table_offset: Option<u64> = None;
    let mut n = 1;
    loop {
        let entry: TocEntry = file.read_le()?;
        if entry.id == 0x8530efef {
            break
        }
        println!("Entry {}. ID: {:02x}, Offset: {}, Size: {}, Type: {:02x}", n, entry.id, entry.offset, entry.size, entry.part_type);

        if entry.id == 0x02 && entry.part_type == 0x00 {
            part_table_offset = Some(entry.offset as u64);
        }

        entries.push(entry);
        n += 1;
    }

    if part_table_offset.is_none() {
        println!("Failed to find partition table offset!");
        return Ok(());
    }

    println!("\nReading partition table at: {}", part_table_offset.unwrap());

    file.seek(SeekFrom::Start(part_table_offset.unwrap()))?;
    let part_header: PartHeader = file.read_le()?;
    println!("Part count: {}", part_header.part_count);

    for i in 0..part_header.part_count {
        let part_entry: PartEntry = file.read_le()?;
        println!("\n{}/{}. {}, ID: {:02x}, Size: {}", i + 1, part_header.part_count, part_entry.name(), part_entry.id, part_entry.size);

        for entry in &entries{
            if entry.id == part_entry.id && entry.size == part_entry.size {
                //println!("- Saving {}.bin, Offset: {}, Size: {}", part_entry.name(), entry.offset, entry.size);
                let current_pos = file.stream_position()?;
                file.seek(SeekFrom::Start(entry.offset as u64))?;
                let data = common::read_exact(&mut file, entry.size as usize)?;

                let output_path = Path::new(&output_folder).join(part_entry.name() + ".bin");

                fs::create_dir_all(&output_folder)?;
                let mut out_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(output_path)?;
            
                out_file.write_all(&data)?;

                println!("- Saved file!");
                file.seek(SeekFrom::Start(current_pos))?;
                break
            }
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
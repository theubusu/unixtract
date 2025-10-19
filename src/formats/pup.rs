use std::path::{Path};
use std::fs::{self, File, OpenOptions};
use std::io;
use binrw::{BinRead, BinReaderExt};
use flate2::read::ZlibDecoder;
use std::io::{Write, Read, Seek, SeekFrom};

use crate::common;

#[derive(BinRead)]
struct Header {
	#[br(count = 4)] _magic_bytes: Vec<u8>,
	_unk1: u32,
    _unk2: u16,
    _flags: u8,
    _unk3: u8,
    _header_size: u16,
    _hash_size: u16,
    file_size: u64,
    entry_count: u16,
    _hash_count: u16,
    _unk4: u32,
}

#[derive(BinRead, Clone)]
struct Entry {
    flags: u32,
    _unk1: u32,
    offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
}
impl Entry {
    fn id(&self) -> u32 {
        self.flags >> 20
    }
    fn is_compressed(&self) -> bool {
        (self.flags & 8) != 0
    }
    fn is_blocked(&self) -> bool {
        (self.flags & 0x800) != 0
    }
    fn is_block_table(&self) -> bool {
        (self.flags & 1) != 0
    }
}

#[derive(BinRead, Clone)]
struct BlockEntry {
    offset: u32,
    size: u32,
}

pub fn is_pup_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"\x4F\x15\x3D\x1D" || header == b"\x54\x14\xF5\xEE" { //ps4, ps5
        true
    } else {
        false
    }
}

fn decompress_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

pub fn extract_pup(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let header: Header = file.read_le()?;

    println!("\nFile info:\nFile size: {}\nEntry count: {}",
            header.file_size, header.entry_count);

    let mut entries: Vec<Entry> = Vec::new();
    let mut block_tables: Vec<Entry> = Vec::new();

    for _i in 0..header.entry_count {
        let entry: Entry = file.read_le()?;
        if entry.is_block_table() {
            block_tables.push(entry.clone())
        }
        entries.push(entry);
    }

    let mut e_i = 0;
    for entry in &entries {
        println!("\n{}/{}: ID: {} Offset: {}, Compressed Size: {}, Uncompressed Size: {}\nCompressed: {}, Blocked: {}, Block table: {}",
            e_i + 1, entries.len(), entry.id(), entry.offset, entry.compressed_size, entry.uncompressed_size, entry.is_compressed(), entry.is_blocked(), entry.is_block_table());

        if !entry.is_block_table () {
        if entry.is_blocked() && entry.is_compressed() {
            let block_size = 2_u32.pow(((entry.flags & 0xF000) >> 12) + 12);
            let block_count = (block_size + entry.uncompressed_size as u32 - 1) / block_size;
            let last_block_size = entry.uncompressed_size % block_size as u64;
            let mut my_block_table: Option<Entry> = None;
            println!("Block size: {}, Block count: {}", block_size, block_count);

            for block_table in &block_tables {
                if block_table.id() == e_i {
                    my_block_table = Some(block_table.clone());
                    println!("Found block table: Offset: {}, Size: {}", block_table.offset, block_table.compressed_size);
                    break
                }
            }
            if my_block_table.is_none() {
                println!("Failed to find block table!");
                continue
            }

            let initial_offset = my_block_table.as_ref().unwrap().offset + (32 * block_count as u64) + (8 * block_count as u64);

            file.seek(SeekFrom::Start(my_block_table.as_ref().unwrap().offset + 32 * block_count as u64))?;

            for i in 0..block_count {
                let block: BlockEntry = file.read_le()?;
                let current_pos = file.stream_position()?;

                let padding = block.size & 0xF;
                let data_size =  // last block in the entire file will be filesize - offste
                if (i == block_count - 1) && (e_i as usize + 1 == entries.len()) {
                    header.file_size as u32 - initial_offset as u32 - block.offset
                } else {
                    block.size - padding
                };
                // last block will have smaller block size
                let ac_block_size = if i == block_count - 1 {last_block_size as u32} else {block_size};

                let compressed = if data_size == ac_block_size {false} else {true};
                println!("Block {}/{}: Offset: {}, Data Size: {}, Padding: {}, Compressed: {}", i + 1, block_count, block.offset, data_size, padding, compressed);

                file.seek(std::io::SeekFrom::Start(initial_offset + block.offset as u64))?;
                let out_data;
                let data = common::read_exact(&mut file, data_size as usize)?;
                if compressed {
                    println!("- Decompressing...");
                    out_data = decompress_zlib(&data)?;
                } else {
                    out_data = data;
                }

                let output_path = Path::new(&output_folder).join(format!("{}.bin", entry.id()));
            
                fs::create_dir_all(&output_folder)?;
                let mut out_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(output_path)?;
            
                out_file.write_all(&out_data)?;

                println!("-- Saved!");

                file.seek(std::io::SeekFrom::Start(current_pos))?;
            }

        } else {
            let data = common::read_file(&file, entry.offset, entry.compressed_size as usize)?;
            let out_data;

            if entry.is_compressed() {
                println!("- Decompressing...");
                out_data = decompress_zlib(&data)?;
            } else {
                out_data = data;
            }

            let output_path = Path::new(&output_folder).join(format!("{}.bin", entry.id()));
            
            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(output_path)?;
            
            out_file.write_all(&out_data)?;

            println!("-- Saved file!");
        }
        } else {
            println!("- Skipping block table..")
        }
        e_i += 1;

    } 

    println!("\nExtraction finished!");
    Ok(())
}
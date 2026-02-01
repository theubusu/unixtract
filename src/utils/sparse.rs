use binrw::{BinRead, BinReaderExt};
use std::fs::OpenOptions;
use std::path::{PathBuf};
use std::io::{Cursor, Seek, SeekFrom, Write};

use crate::utils::common;

#[derive(BinRead)]
struct SparseHeader {
    #[br(count = 4)] magic_bytes: Vec<u8>,
    _major_version: u16,
    _minor_version: u16,
    _file_header_size: u16,
    _chunk_header_size: u16,
    block_size: u32,
    _total_blocks: u32,
    total_chunks: u32,
    _image_checksum: u32
}

#[derive(BinRead, Debug)]
struct ChunkHeader {
    chunk_type: u16,
    _reserved1: u16,
    chunk_size: u32,
    total_size: u32,
}

pub fn unsparse_to_file(data: &[u8], file_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut data_reader = Cursor::new(data);
    let file_header: SparseHeader = data_reader.read_le()?;
    if file_header.magic_bytes != b"\x3A\xFF\x26\xED" {
        return Err("Invalid magic!".into());
    }

    let mut out_file = OpenOptions::new().create(true).read(true).write(true).open(file_path)?;

    for _i in 0..file_header.total_chunks{
        let chunk_header: ChunkHeader = data_reader.read_le()?;
        let chunk_data = common::read_exact(&mut data_reader, chunk_header.total_size as usize - 12)?;

        if chunk_header.chunk_type == 0xCAC1 { //"raw" type chunk (actual data)
            out_file.write_all(&chunk_data)?; 

        } else if chunk_header.chunk_type == 0xCAC2 { // "fill" type chunk (fill size with a value)
            if chunk_data.len() != 4 {
                return Err("Inavlid lenght of FILL chunk!".into());
            }
            let fill_size = (chunk_header.chunk_size * file_header.block_size) / 4;
            let fill_data = chunk_data.repeat(fill_size as usize);

            out_file.write_all(&fill_data)?; 

        } else if chunk_header.chunk_type == 0xCAC3 { // "dont care" type chunk (skip over)
            let skip_size = file_header.block_size as u64 * chunk_header.chunk_size as u64;
            let current_pos = out_file.stream_position()?;
            let new_pos = current_pos + skip_size;

            //enlarge file with zeros if the seek is larger than file
            let current_file_size = out_file.metadata()?.len();
            if new_pos > current_file_size {
                out_file.set_len(new_pos)?;
            }
            
            out_file.seek(SeekFrom::Start(new_pos))?;
        }
    }

    Ok(())

}
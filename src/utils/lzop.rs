use binrw::{BinRead, BinReaderExt};
use std::io::{Cursor};

use simd_adler32::adler32;
use crate::common;

#[derive(BinRead)]
struct LzopHeader {
    #[br(count = 9)] magic_bytes: Vec<u8>,
    _version: u16,
    _lib_version: u16,
    _version_needed_to_extract: u16,
    method: u8,
    _level: u8,
    _flags: u32,
    _mode: u32,
    _mtime_low: u32,
    _mtime_high: u32,
    _name_len: u8,
    #[br(count = _name_len)] _name_bytes: Vec<u8>,
    _header_checksum: u32,
}

#[derive(BinRead, Debug)]
struct SegmentHeader {
    uncompressed_size: u32,
    compressed_size: u32,
    checksum: u32,
}

pub fn decompress_lzop(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_reader = Cursor::new(data);
    let header: LzopHeader = data_reader.read_be()?;
    if header.magic_bytes != b"\x89LZO\x00\x0D\x0A\x1A\x0A" {
        return Err("Invalid magic!".into());
    }
    if ![1, 2, 3].contains(&header.method) {
        return Err("Unsupported compression method!".into());
    }

    let lzo = minilzo_rs::LZO::init()?;
    let mut decompressed_output = Vec::new();
    loop {
        if (data.len() as u64 - data_reader.position()) < 12 { //check if there are enough bytes to read a segment header
            break;
        }
        let segment_header: SegmentHeader = data_reader.read_be()?;
        if segment_header.compressed_size > segment_header.uncompressed_size {
            println!("{:?}", segment_header);
        }
        //println!("{:?}", segment_header);
        if segment_header.uncompressed_size == 0 {
            break
        }

        let stored_data = common::read_exact(&mut data_reader, segment_header.compressed_size as usize)?;
        let out_data = 
        if segment_header.uncompressed_size == segment_header.compressed_size { //if uncomp size = comp size, this segment is not compressed
            stored_data
        } else {
            lzo.decompress(&stored_data, segment_header.uncompressed_size as usize)?
        };

        let calc_checksum = adler32(&out_data.as_slice());
        if calc_checksum != segment_header.checksum {
            return Err("Invalid segment checksum! Data corrupted?".into());
        };

        decompressed_output.extend_from_slice(&out_data);
    }

    Ok(decompressed_output)
}
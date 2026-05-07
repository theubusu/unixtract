use std::fs::OpenOptions;
use std::io::{Write, Cursor, Seek, SeekFrom, Read};
use binrw::{BinRead, BinReaderExt};
use std::path::{PathBuf};

use super::huffman_tables::{CHARLEN, POS};
use crate::utils::common;
use crate::utils::compression::{decompress_lz4, decompress_zstd};

#[derive(PartialEq, Debug)]
enum CompressionType {
    LZHS,
    LZ4,
    ZSTD,
}

#[derive(BinRead)]
struct LzhsHeader {
    uncompressed_size: u32,
    compressed_size: u32,
    checksum_or_seg_idx: u32, //as checksum in normal lzhs header, as index in lzhs_fs header
    _padding: [u8; 4],
}

#[derive(BinRead)]
struct LzhsOldSegmentHdr {
    _uncompressed_size: u32,
    _compressed_size: u32,
}

pub fn decompress_mtk_to_file(data: &[u8], output_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut out_file = OpenOptions::new().append(true).create(true).open(&output_file)?;
    let mut data_reader = Cursor::new(data);

    let uncompressed_heading = common::read_exact(&mut data_reader, 0x100000)?; //first 1mb is uncompressed
    out_file.write_all(&uncompressed_heading)?;

    while data_reader.stream_position().unwrap() < data_reader.get_ref().len() as u64{
        let segment_header: LzhsHeader = data_reader.read_le()?;
        let comp_header: LzhsHeader = data_reader.read_le()?;

        println!("[cmp] Segment {} - Compressed size: {}, Decompressed size: {}",
                segment_header.checksum_or_seg_idx, comp_header.compressed_size, comp_header.uncompressed_size);

        let compressed_data = common::read_exact(&mut data_reader, comp_header.compressed_size as usize)?;

        //set comp method
        let compression_type: CompressionType;
        if comp_header.checksum_or_seg_idx & 0xFFFFFF00 != 0 {    //LZHS uses only a 8 bit checksum, and other use 32 bit(although the type is unknown).
            if compressed_data.starts_with(b"\x28\xB5\x2F\xFD") {   //ZSTD magic
                compression_type = CompressionType::ZSTD;
            } else {
                compression_type = CompressionType::LZ4;
            }
        } else {
            compression_type = CompressionType::LZHS;
        }

        let mut out_data;
        if comp_header.compressed_size == 0 {
            //odd variant no.1: if the compressed size is 0 , the output is just zeros with the uncompressed size.
            out_data = vec![0; comp_header.uncompressed_size as usize];

        } else if (comp_header.uncompressed_size > segment_header.uncompressed_size) && 
                  (comp_header.compressed_size == comp_header.uncompressed_size) &&
                  comp_header.checksum_or_seg_idx == 0x00 
        {
            //odd variant no.2: the lzhs header compressed size is for some reason bigger by 8 bytes (and those 8 bytes are zeros), the data is stored UNCOMPRESSED in these
            //the compressed and uncompressed size are the same and the checksum is 0.
            out_data = compressed_data[..segment_header.uncompressed_size as usize].to_vec();

        } else {
            //normal variant
            println!("- Decompressing {:?}...", compression_type);
            if compression_type == CompressionType::LZ4 {
                out_data = decompress_lz4(&compressed_data, comp_header.uncompressed_size as i32)?;
            }
            else if compression_type == CompressionType::ZSTD {
                out_data = decompress_zstd(&compressed_data)?;
            }
            else if compression_type == CompressionType::LZHS {
                let out_huff = unhuff(&compressed_data);
                out_data = unlzss(&out_huff, comp_header.uncompressed_size as usize);
                arm_thumb_convert(&mut out_data, 0, false);

                let checksum = calc_checksum(&out_data);
                println!("-- Calculated checksum: 0x{:02x?}", checksum);
                if u32::from(checksum) != comp_header.checksum_or_seg_idx {
                    println!("--- Checksum mismatch! Expected: 0x{:02x?}, Got: 0x{:02x?}!", comp_header.checksum_or_seg_idx, checksum);
                    return Err("LZHS checksum mismatch".into());
                } else {
                    println!("--- Checksum OK!")
                }
            }
            else {
                return Err("undefined compression type".into());
            }      
        }

        out_file.write_all(&out_data)?;
        
        //padded to 16 bytes
        let pad_pos = (data_reader.stream_position().unwrap() + 15) & !15;
        data_reader.seek(SeekFrom::Start(pad_pos))?;
    }

    Ok(())
}

// OLD VARIANT use in old mtk pkg
pub fn decompress_mtk_to_file_old(data: &[u8], output_file: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut out_file = OpenOptions::new().append(true).create(true).open(&output_file)?;
    let mut data_reader = Cursor::new(data);

    let uncompressed_heading = common::read_exact(&mut data_reader, 0x200)?; //first 1mb is uncompressed
    out_file.write_all(&uncompressed_heading)?;

    while data_reader.stream_position().unwrap() < data_reader.get_ref().len() as u64{
        let _segment_header: LzhsOldSegmentHdr = data_reader.read_le()?;
        let lzhs_header: LzhsHeader = data_reader.read_le()?;

        println!("[LZHS] Segment - Compressed size: {}, Decompressed size: {}, Expected Checksum: 0x{:02x?}",
                lzhs_header.compressed_size, lzhs_header.uncompressed_size, lzhs_header.checksum_or_seg_idx);

        let compressed_data = common::read_exact(&mut data_reader, lzhs_header.compressed_size as usize)?;
        let mut out_data;
        let out_huff = unhuff(&compressed_data);
        out_data = unlzss(&out_huff, lzhs_header.uncompressed_size as usize);
        arm_thumb_convert(&mut out_data, 0, false);

        let checksum = calc_checksum(&out_data);
        println!("-- Calculated checksum: 0x{:02x?}", checksum);
        if u32::from(checksum) != lzhs_header.checksum_or_seg_idx {
            println!("--- Checksum mismatch! Expected: 0x{:02x?}, Got: 0x{:02x?}!", lzhs_header.checksum_or_seg_idx, checksum);
            return Err("LZHS checksum mismatch".into());
        } else {
            println!("--- Checksum OK!")
        }
        
        out_file.write_all(&out_data)?;
    }

    Ok(())
}

#[derive(Debug)]
struct HuffmanCtx {
    c: u8,
    code: u32,
    len: u32,
    bitno: u8,
    code_buf: [u8; 32],
    code_buf_ptr: usize,
    mask: u8,
}

fn get_byte<Cursor: Read>(ctx: &mut HuffmanCtx, input: &mut Cursor) -> bool {
    if ctx.bitno > 7 {
        ctx.bitno = 0;
        let mut buf = [0u8; 1];
        if input.read_exact(&mut buf).is_err() {
            return false;
        }
        ctx.c = buf[0];
    }
    let bit = ((ctx.c >> (7 - ctx.bitno)) & 1) as u32;
    ctx.code = (ctx.code << 1) | bit;
    ctx.len += 1;
    ctx.bitno += 1;
    true
}

fn unhuff(data: &[u8]) -> Vec<u8> {
    let charlen = &CHARLEN;
    let pos = &POS;

    let mut ctx = HuffmanCtx {
        c: 0,
        code: 0,
        len: 0,
        bitno: 8,
        code_buf: [0u8; 32],
        code_buf_ptr: 1,
        mask: 1,
    };
    let mut lookup_charlen = vec![-1i16; 131072];
    let mut lookup_charpos = vec![-1i16; 512];

    let mut in_cur = Cursor::new(data);
    let mut out: Vec<u8> = Vec::with_capacity(data.len());

    loop {
        if !get_byte(&mut ctx, &mut in_cur) { /*println!("break1");*/break; }
        if ctx.len < 4 { continue; }
        let key = (((ctx.len & 0xF) as usize) << 13) | ((ctx.code & 0x1FFF) as usize);
        let mut idx = lookup_charlen[key];
        if idx == -2 { continue; }
        if idx == -1 {
            let mut found = false;
            for (i, &(code, len)) in charlen.iter().enumerate() {
                if len == ctx.len && code == ctx.code {
                    lookup_charlen[key] = i as i16;
                    idx = i as i16; found = true; break;
                }
            }
            if !found { lookup_charlen[key] = -2; continue; }
        }
        let i = idx as i32;
        if i > 255 {
            let val = (i - 256) as u8;
            if ctx.code_buf_ptr < ctx.code_buf.len() { ctx.code_buf[ctx.code_buf_ptr] = val; ctx.code_buf_ptr += 1; }
            ctx.code = 0; ctx.len = 0;

            let found_j: i32;
            loop {
                if !get_byte(&mut ctx, &mut in_cur) {	
					//println!("retA");
					//flush
					if ctx.code_buf_ptr > 1 { for j in 0..ctx.code_buf_ptr { out.push(ctx.code_buf[j]); } };
					return out;
				}
                if ctx.len < 2 { continue; }
                let keyp = (((ctx.len & 0x7) as usize) << 6) | ((ctx.code & 0x3F) as usize);
                let mut jdx = lookup_charpos[keyp];
                if jdx == -2 { continue; }
                if jdx == -1 {
                    let mut found = false;
                    for (j, &(code, len)) in pos.iter().enumerate() {
                        if len == ctx.len && code == ctx.code {
                            lookup_charpos[keyp] = j as i16; jdx = j as i16; found = true; break;
                        }
                    }
                    if !found { lookup_charpos[keyp] = -2; continue; }
                }
                found_j = jdx as i32;
                let b = ((jdx as i32) >> 1) as u8;
                if ctx.code_buf_ptr < ctx.code_buf.len() { ctx.code_buf[ctx.code_buf_ptr] = b; ctx.code_buf_ptr += 1; }
				break;
            }
            ctx.code = 0;
            for _ in 0..7 { if !get_byte(&mut ctx, &mut in_cur) {
				//println!("retB");
				//flush
				if ctx.code_buf_ptr > 1 { for j in 0..ctx.code_buf_ptr { out.push(ctx.code_buf[j]); } };
				return out;
				}
			}
            let combined = (ctx.code | ((found_j as u32) << 7)) as u32;
            if ctx.code_buf_ptr < ctx.code_buf.len() { ctx.code_buf[ctx.code_buf_ptr] = (combined & 0xFF) as u8; ctx.code_buf_ptr += 1; }
            ctx.code = 0; ctx.len = 0;
        } else {
            ctx.code_buf[0] |= ctx.mask;
            if ctx.code_buf_ptr < ctx.code_buf.len() { ctx.code_buf[ctx.code_buf_ptr] = i as u8; ctx.code_buf_ptr += 1; }
            ctx.code = 0; ctx.len = 0;
        }
        ctx.mask = ctx.mask.wrapping_shl(1);
        if ctx.mask == 0 {
            for j in 0..ctx.code_buf_ptr { out.push(ctx.code_buf[j]); }
            ctx.code_buf[0] = 0; ctx.code_buf_ptr = 1; ctx.mask = 1;
        }
    }
    if ctx.code_buf_ptr > 1 { for j in 0..ctx.code_buf_ptr { out.push(ctx.code_buf[j]); } }
    out
}

fn unlzss(data: &[u8], expected_size: usize) -> Vec<u8> {
    let mut window = [0u8; 0x1000];
    let mut dst = Vec::with_capacity(expected_size);
    let mut src_i = 0;
    let mut win_pos = 0usize;
    let mut flags = 0u32;

    while dst.len() < expected_size {
        flags >>= 1;
        if (flags & 0x100) == 0 {
            if src_i >= data.len() {
                break;
            }
            flags = data[src_i] as u32 | 0xFF00;
            src_i += 1;
        }

        if (flags & 1) != 0 {
            // literal
            if src_i >= data.len() {
                break;
            }
            let c = data[src_i];
            src_i += 1;
            dst.push(c);
            window[win_pos] = c;
            win_pos = (win_pos + 1) & 0xFFF;
        } else {
            // backreference
            if src_i + 2 >= data.len() {
                break;
            }
            let j = data[src_i] as usize;
            let off = ((data[src_i + 1] as usize) << 8) | data[src_i + 2] as usize;
            src_i += 3;

            let count = j + 3;
            for _ in 0..count {
                if dst.len() >= expected_size {
                    break;
                }
                let c = window[(win_pos.wrapping_sub(off)) & 0xFFF];
                dst.push(c);
                window[win_pos] = c;
                win_pos = (win_pos + 1) & 0xFFF;
            }
        }
    }

    dst
}

fn arm_thumb_convert(data: &mut [u8], now_pos: u32, encoding: bool) {
    let size = data.len() as u32;
    let mut i: u32 = 0;

    while i + 4 <= size {
        let idx = i as usize;

        if (data[idx + 1] & 0xF8) == 0xF0 && (data[idx + 3] & 0xF8) == 0xF8 {
            let mut src: u32 =
                ((data[idx + 1] as u32 & 0x7) << 19) |
                ((data[idx + 0] as u32) << 11) |
                ((data[idx + 3] as u32 & 0x7) << 8) |
                (data[idx + 2] as u32);

            src <<= 1;

            let dest = if encoding {
                now_pos + i + 4 + src
            } else {
                src.wrapping_sub(now_pos + i + 4)
            } >> 1;

            data[idx + 1] = 0xF0 | ((dest >> 19) & 0x7) as u8;
            data[idx + 0] = ((dest >> 11) & 0xFF) as u8;
            data[idx + 3] = 0xF8 | ((dest >> 8) & 0x7) as u8;
            data[idx + 2] = (dest & 0xFF) as u8;

            i += 2;
        }

        i += 2;
    }
}

fn calc_checksum(data: &[u8]) -> u8 {
    let mut checksum: u8 = 0;
    for &bt in data {
        checksum = checksum.wrapping_add(bt);
    }
    checksum
}
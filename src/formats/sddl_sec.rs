use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use flate2::read::ZlibDecoder;

use crate::common;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};

pub fn is_sddl_sec_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 8).expect("Failed to read from file.");
    if header == b"\x12\xB8\x02\x8C\x6F\xC6\xBD\x15" {
        true
    } else {
        false
    }
}

//ported from original from https://nese.team/posts/justctf/
fn decipher(s: &[u8], len_: usize) -> Vec<u8> {
    let mut v3: u32 = 904;
    let mut out = s.to_vec();
    let mut cnt = 0;
    
    if len_ > 0 {
        let true_len = if len_ >= 0x80 {
            128
        } else {
            len_
        };
        
        if true_len > 0 {
            let mut i = 0;
            let mut j: u8 = 0;
            
            while i < s.len() {
                let iter_ = s[i];
                i += 1;
                j = j.wrapping_add(1);
                
                let v11 = (iter_ as u32).wrapping_add(38400) & 0xffffffff;
                let v12 = iter_ ^ ((v3 & 0xff00) >> 8) as u8;
                v3 = v3.wrapping_add(v11).wrapping_add(163) & 0xffffffff;
                
                if j == 0 {
                    v3 = 904;
                }
                
                if cnt < out.len() {
                    out[cnt] = v12;
                    cnt += 1;
                }
            }
        }
    }
    
    out
}

fn decompress_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

pub fn extract_sddl_sec(file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {

    let file_size = file.metadata()?.len();

    let key = [
        0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
        0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
    ];
    
    let iv = [
        0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
        0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
    ];

    let mut offset = 32;

    while offset < file_size {
        let header = common::read_file(&file, offset, 32)?;
        let decrypted_header: Vec<u8>; 

        match decrypt_aes128_cbc_pcks7(&header, &key, &iv) {
            Ok(v) => decrypted_header = v,
            Err(_) => {
                // SDDL files can have a footer(signature?) of 0x80 OR 0x100 lenght in later ones, and there is no good way to detect it before entering the while loop and the footer has no common header.
                // so we can assume if a file fails to decode at negative offsets 0x80 or 0x100, that is the footer and it can be skipped.
                if offset == file_size - 128 {
                    break
                } else if offset == file_size - 256{
                    break
                } else {
                    println!("!!Decryption error!! This file is invalid or not compatible!");
                    std::process::exit(0)
                }
            },
        }

        let decrypted_string = String::from_utf8_lossy(&decrypted_header);

        let filename = decrypted_string.split("\0").next().unwrap();
        let size_str = &decrypted_string[decrypted_string.len() - 12..];
        let size: u64 = size_str.parse().unwrap();

        println!("\nFile: {}, Size: {}", filename, size);
        
        offset += 32;

        let data = common::read_file(&file, offset, size.try_into().unwrap())?;
        let decrypted_data = decrypt_aes128_cbc_pcks7(&data, &key, &iv)?;

        if decrypted_data.starts_with(&[0x11, 0x22, 0x33, 0x44]) && filename != "SDIT.FDI"{ // header of obfuscated file, SDIT.FDI also has this header but seems to work differently so its skipped

            println!("- Version: {}.{}{}{}", decrypted_data[24], decrypted_data[25], decrypted_data[26], decrypted_data[27]);
            println!("- Deciphering...");
            let deciphered_data = decipher(&decrypted_data[48..], decrypted_data[48..].len());

            let control_byte = decrypted_data[34];
            let out_data: Vec<u8>; 

            if control_byte == 3 {
                println!("-- Decompressing...");
                out_data = decompress_zlib(&deciphered_data)?;
            } else {
                println!("-- Uncompressed...");
                out_data = deciphered_data;
            }

            let first_byte;
            if out_data[1] & 0xF0 == 0xD0 {
                first_byte = out_data[1] & 0x0F;
            } else {
                first_byte = out_data[1];
            }

            let dest_offset = u32::from_be_bytes([first_byte, out_data[2], out_data[3], out_data[4]]);

            let source_offset = u32::from_be_bytes([0x00, out_data[6], out_data[7], out_data[8]]);

            let path: PathBuf; 
            let msg: String;

            let source_name = filename.split(".").next().unwrap();

            if source_offset == 270 {   //unique for 2014-2018 files
                let embedded_file_name_string = String::from_utf8_lossy(&out_data[14..270]);
                let embedded_file_name = embedded_file_name_string.split("\0").next().unwrap();
                println!("--- Embedded file: {}", embedded_file_name);
    
                let folder_path = Path::new(&output_folder).join(source_name);
                fs::create_dir_all(&folder_path)?;
                path = Path::new(&folder_path).join(embedded_file_name);
                msg = format!("to {}", source_name);
            } else {
                path = Path::new(&output_folder).join(format!("{}.bin", source_name));
                msg = format!("to {}.bin", source_name);
            }

            fs::create_dir_all(&output_folder)?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?;
    
            file.seek(SeekFrom::Start(dest_offset as u64))?;
            file.write_all(&out_data[source_offset as usize..])?;
            println!("--- Saved {}!", msg);

        } else {
            let out_data = decrypted_data;
            if filename.ends_with(".TXT") {
                println!("{}", String::from_utf8_lossy(&out_data));
            } else {
                let path = Path::new(&output_folder).join(filename);

                fs::create_dir_all(&output_folder)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(path)?;
  
                file.write_all(&out_data)?;
                println!("-- Saved file!");
            } 
        }

        offset += size;
    }

    println!("\nExtraction finished!");

    Ok(())
}
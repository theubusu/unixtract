use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Cursor, Seek};

use crate::utils::common;

fn decrypt_xor(data: &[u8]) -> Vec<u8> {
    let key_bytes = b"\xCC\xF0\xC8\xC4\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA";
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

pub fn is_rvp_file(mut file: &File) -> bool {
    //MVP
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"UPDT" {
        file.seek(std::io::SeekFrom::Start(36)).expect("Failed to seek"); //skip rest of header
        return true;
    }

    //RVP
    let bytes = common::read_file(&file, 16, 18).expect("Failed to read from file.");
    for (_i, &b) in bytes.iter().enumerate().step_by(2) {
        if b != 0xA3 {
            return false;
        }
    }
    file.seek(std::io::SeekFrom::Start(64)).expect("Failed to seek"); //skip rest of header
    true
}

pub fn extract_rvp(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut obf_data = Vec::new();  //we sadly cannot deXOR on the fly because of its 32 byte pattern
    file.read_to_end(&mut obf_data)?;
    println!("DeXORing data..");
    let data = decrypt_xor(&obf_data); 
    let mut data_reader = Cursor::new(data);

    let _unknown = common::read_exact(&mut data_reader, 256)?; //seems to be mostly the same between files

    let mut i = 0;
    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        i += 1;
        let header_size_bytes = common::read_exact(&mut data_reader, 4)?;
        let header_size = u32::from_be_bytes(header_size_bytes.try_into().unwrap());
        println!("\n#{} - Offset: {}, Header size: {}", i, data_reader.position() - 4, header_size);
        let hdr = common::read_exact(&mut data_reader, header_size as usize)?;

        let size;
        let mut name = String::new();
        if i == 1 { //first entry always has this big header
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();
            //1. maybe target? always "ALL" in japanese, "BD-HP50" in usa hp50
            //2. always "host"
            //3. unknown, like "0B01"
            //4. unknown, like "00000111"
            //5. always "FFFF"
            //6. always "FFFF"
            //7. always "3" or "0"
            //8. always "88005004"
            //9. always "88005004"
            //10. always "88005000"
            //11. size as decimal string, like "12320768"
            //12. unknown, differing hex string like "F8833EE1"
            //13. crc32 checksum like "3827E120"
            let target = &lines[0];
            size = lines[10].parse().unwrap();
            let crc32 = &lines[12];
            println!("Target: {}", target);
            println!("CRC32: {}", crc32);

        } else if header_size == 32 {
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();
            //1. CRC32 checksum like "34D0757C"
            //2. unknown - "FFFFFFFF"
            //3. size in hex string like "00040000"
            let crc32 = &lines[0];
            size = u32::from_str_radix(&lines[2], 16).unwrap();
            println!("CRC32: {}", crc32);

        } else if header_size == 48 || header_size == 44 || header_size == 40 {
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();
            //1. - name, like "L12_110.IMG"
            //2. - size in hex string like "001E6388"
            //3. - unknown - single number like "3"
            //4. - crc32 checksum like "0BC0F6F7"
            //5. - unknown - like "00011200" -- this line is not present when size is 40 but were not using it anyway so whatever
            name = lines[0].clone();
            size = u32::from_str_radix(&lines[1], 16).unwrap();
            let crc32 = &lines[3];
            println!("File name: {}", name);
            println!("CRC32: {}", crc32);

        } else if header_size == 16 {
            // 4 bytes CRC32
            // 4 bytes unknown "FF FF FF FF"
            // 4 bytes size
            // 4 bytes unknown "00 00 00 00"
            let crc32 = hex::encode_upper(&hdr[0..4]);
            size = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
            println!("CRC32: {}", crc32);

        } else {
            println!("Unsupported header size!");
            break

        }

        println!("Size: {}", size);
        let data = common::read_exact(&mut data_reader, size as usize)?;
        let output_path = Path::new(&output_folder).join(if name=="" {format!("{}.bin", i)} else {format!("{}_{}.bin", i, name)});

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;      
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
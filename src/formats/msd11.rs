use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Cursor, Write, Seek, SeekFrom};

use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;

use crate::common;
use crate::keys;

pub fn is_msd11_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 6).expect("Failed to read from file.");
    if header == b"MSDU11" {
        true
    } else {
        false
    }
}

struct Section {
    index: u32,
    offset: u64,
    size: u64,
    name: String,
}

fn decrypt_aes_salted_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    assert!(data[0..8].to_vec() == b"Salted__", "invalid encrypted data!");
    let salt = &data[8..16];

    //iv = md5 of salt
    let iv = md5::compute(&salt);

    let decryptor = Aes128CbcDec::new((&(**passphrase_bytes)).into(), (&iv.0).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data[16..])
        .map_err(|e| format!("Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

fn decrypt_aes_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    //iv = md5 of salt
    let iv = md5::compute(&salt);

    let decryptor = Aes128CbcDec::new((&(**passphrase_bytes)).into(), (&iv.0).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

pub fn extract_msd11(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    
    let _magic = common::read_exact(&mut file, 6)?; //MSDU11 magic

    let _ = common::read_exact(&mut file, 12)?;

    let section_count_bytes = common::read_exact(&mut file, 4)?;
    let section_count = u32::from_le_bytes(section_count_bytes.try_into().unwrap());
    println!("\nNumber of sections: {}", section_count);

    let mut sections: Vec<Section> = Vec::new();

    //parse sections
    for _i in 0..section_count {
        let index_bytes = common::read_exact(&mut file, 4)?;
        let index = u32::from_le_bytes(index_bytes.try_into().unwrap());

        let offset_bytes = common::read_exact(&mut file, 8)?;
        let offset = u64::from_le_bytes(offset_bytes.try_into().unwrap());

        let size_bytes = common::read_exact(&mut file, 8)?;
        let size = u64::from_le_bytes(size_bytes.try_into().unwrap());

        println!("Section {}: offset: {}, size: {}", index, offset, size);
        sections.push(Section { index, offset, size , name: "".to_string() });
    }

    let header_count_bytes = common::read_exact(&mut file, 4)?;
    let header_count = u32::from_le_bytes(header_count_bytes.try_into().unwrap());
    println!("\nNumber of headers: {}", header_count);

    let mut headers: Vec<Section> = Vec::new();

    //parse headers
    for i in 0..header_count {
        let offset_bytes = common::read_exact(&mut file, 8)?;
        let offset = u64::from_le_bytes(offset_bytes.try_into().unwrap());

        let size_bytes = common::read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        let name_length_byte = common::read_exact(&mut file, 1)?;
        let name_length = u8::from_le_bytes(name_length_byte.try_into().unwrap());

        let name_bytes = common::read_exact(&mut file, name_length as usize)?;
        let name = String::from_utf8(name_bytes)?;

        println!("Header {}: {}, offset: {}, size: {}", i + 1, name, offset, size);

        headers.push(Section { index: 0, offset, size: size as u64 , name });
    }

    //use first header
    let firmware_name = &headers[0].name;
    println!("\nFirmware name: {}", firmware_name);

    let mut passphrase: Option<&str> = None;
    let passphrase_bytes;

    //find passphrase
    for (prefix, value) in keys::MSD11 {
        if firmware_name.starts_with(prefix) {
            passphrase = Some(value);
            break;
        }
    }
    if let Some(p) = passphrase {
        println!("Passphrase: {}", p);
        passphrase_bytes = hex::decode(p)?;
    } else {
        println!("Sorry, this firmware is not supported!");
        std::process::exit(1);
    }

    let toc_offset = headers[0].offset + 8;
    let toc_size = headers[0].size - 8;
    let toc_data = common::read_file(&file, toc_offset as u64, toc_size as usize)?;

    //parse TOC
    let toc = decrypt_aes_salted_tizen(&toc_data, &passphrase_bytes)?;
    let mut toc_reader = Cursor::new(toc);

    toc_reader.seek(SeekFrom::Current(262))?; // probably signature
    toc_reader.seek(SeekFrom::Current(50))?; // Tizen Software Upgrade Tree Binary Format ver. 1.9

    for i in 0..section_count {
        toc_reader.seek(SeekFrom::Current(74))?; //unknown

        let name_length_byte = common::read_exact(&mut toc_reader, 1)?;
        let name_length = u8::from_le_bytes(name_length_byte.try_into().unwrap());

        let name_bytes = common::read_exact(&mut toc_reader, name_length as usize)?;
        let name = String::from_utf8(name_bytes)?;

        toc_reader.seek(SeekFrom::Current(39))?; //unknown

        let salt = common::read_exact(&mut toc_reader, 8)?;

        toc_reader.seek(SeekFrom::Current(267))?; //unknown

        println!("\nSection {}: {}", sections[i as usize].index, name);

        let offset = sections[i as usize].offset;
        let size = sections[i as usize].size;
        let encrypted_data = common::read_file(&file, offset as u64, size as usize)?;

        println!("- Decrypting...");
        let decrypted_data = decrypt_aes_tizen(&encrypted_data, &passphrase_bytes, &salt)?;

        let output_path = Path::new(&output_folder).join(name);

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&decrypted_data)?;

        println!("-- Saved file!");

    }

    println!("\nExtraction finished!");

    Ok(())
}
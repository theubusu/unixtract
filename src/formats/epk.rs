use std::fs::File;

use crate::utils::common;
use crate::formats;

pub fn is_epk_file(file: &File) -> bool {
    let versions = common::read_file(&file, 1712, 36).expect("Failed to read from file.");

    if check_epk_version(&versions).is_some() {
        true
    } else {
        false
    }
}

fn check_epk_version(versions: &[u8]) -> Option<String> {
    //                      _ - 0x00     X - a number    . - a dot
    let epk2_pattern =     "____XXXX.XXXX.XXXX__XX.XX.XXX_______";
    let epk3_pattern =     "____X.X.X___________X.X.X___________";
    let epk3_new_pattern = "____XX.X.X__________XX.X.X__________";

    if match_with_pattern(&versions, epk2_pattern) {
        Some("epk2".to_string())
    } else if match_with_pattern(&versions, epk3_pattern) {     
        Some("epk3".to_string())
    } else if match_with_pattern(&versions, epk3_new_pattern) {     
        Some("epk3".to_string())
    }else {
        None
    }
}

fn match_with_pattern(data: &[u8], pattern: &str) -> bool {
    for (&b, p) in data.iter().zip(pattern.bytes()) {
        match p {
            b'_' if b != 0x00           => return false,
            b'X' if !b.is_ascii_digit() => return false,
            b'.' if b != b'.'           => return false,
            _ => {}
        }
    }
    true
}

pub fn extract_epk(file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let versions = common::read_file(&file, 1712, 36)?;
    let epk_version = check_epk_version(&versions);

    let platform_version = common::string_from_bytes(&versions[4..20]);
    let sdk_version = common::string_from_bytes(&versions[20..36]);
    println!("Platform version: {}\nSDK version: {}", platform_version, sdk_version);
    
    if epk_version == Some("epk2".to_string()) {
        println!("EPK2 detected!\n");
        formats::epk2::extract_epk2(file, output_folder)?;
    } else if epk_version == Some("epk3".to_string()) {
        println!("EPK3 detected!\n");
        formats::epk3::extract_epk3(file, output_folder)?;
    }

    Ok(())
}

//COMMON EPK FUNCTIONS
pub fn find_key<'a>(key_array: &'a [(&'a str, &'a str)], data: &[u8], expected_magic: &[u8]) -> Result<Option<(&'a str, Vec<u8>)>, Box<dyn std::error::Error>> {
    for (key_hex, name) in key_array {
        let key_bytes = hex::decode(key_hex)?;
        let decrypted = match decrypt_aes_ecb_auto(&key_bytes, data) {
            Ok(d) => d,
            Err(_) => continue,
        };
     
        if decrypted.starts_with(expected_magic) {
            return Ok(Some((name, key_bytes)));
        }
    }
    Ok(None)
}

use aes::Aes128;
use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

type Aes128EcbDec = Decryptor<Aes128>;
type Aes256EcbDec = Decryptor<Aes256>;

pub fn decrypt_aes_ecb_auto(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.to_vec();

    if key.len() == 32 {
        // aes256
        let key_array: [u8; 32] = key.try_into()?;
        let mut decryptor = Aes256EcbDec::new(&key_array.into());
        for chunk in buffer.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into()?;
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    } else {
        // aes128
        let key_array: [u8; 16] = key.try_into()?;
        let mut decryptor = Aes128EcbDec::new(&key_array.into());
        for chunk in buffer.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into()?;
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    }

    Ok(buffer)
}
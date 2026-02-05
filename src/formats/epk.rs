use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "epk", detector_func: is_epk_file, extractor_func: extract_epk }
}

use crate::utils::common;
use crate::formats;

pub struct EpkContext {
    epk_version: u8,
}

pub fn is_epk_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let versions = common::read_file(app_ctx.file, 1712, 36)?;

    if let Some(epk_version) = check_epk_version(&versions) {
        Ok(Some(Box::new(EpkContext {epk_version})))
    } else {
        Ok(None)
    }
}

fn check_epk_version(versions: &[u8]) -> Option<u8> {
    //                      _ - 0x00     X - a number    . - a dot
    let epk2_pattern =     "____XXXX.XXXX.XXXX__XX.XX.XXX_______";
    let epk3_pattern =     "____X.X.X___________X.X.X___________";
    let epk3_new_pattern = "____XX.X.X__________XX.X.X__________";

    if match_with_pattern(&versions, epk2_pattern) {
        Some(2)
    } else if match_with_pattern(&versions, epk3_pattern) {     
        Some(3)
    } else if match_with_pattern(&versions, epk3_new_pattern) {     
        Some(3)
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

pub fn extract_epk(app_ctx: &AppContext, ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx.and_then(|c| c.downcast::<EpkContext>().ok()).ok_or("Context is invalid or missing!")?;

    let versions = common::read_file(app_ctx.file, 1712, 36)?;

    let platform_version = common::string_from_bytes(&versions[4..20]);
    let sdk_version = common::string_from_bytes(&versions[20..36]);
    println!("Platform version: {}\nSDK version: {}", platform_version, sdk_version);
    
    if ctx.epk_version == 2 {
        println!("EPK2 detected!\n");
        formats::epk2::extract_epk2(app_ctx, None)?;
    } else if ctx.epk_version == 3 {
        println!("EPK3 detected!\n");
        formats::epk3::extract_epk3(app_ctx, None)?;
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
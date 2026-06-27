//MSD OUITH parsers
pub mod msd_ouith_parser_old;
pub mod msd_ouith_parser_tizen_1_8;
pub mod msd_ouith_parser_tizen_1_9;

// COMMON MSD FUNCTIONS
use aes::{Aes128, Aes256};
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;
type Aes256CbcDec = Decryptor<Aes256>;

use sha2::{Digest, Sha256};

pub fn decrypt_aes_salted_old(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    if data[0..8].to_vec() != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }
    let salt = &data[8..16];

    //key = md5 of (passphrase + salt)
    let mut key = Vec::new();
    key.extend_from_slice(&passphrase_bytes);
    key.extend_from_slice(&salt);
    let key_md5 = md5::compute(&key);

    //iv = md5 of (md5 of key + passphrase + salt)
    let mut iv = Vec::new();
    iv.extend_from_slice(&key_md5.0);
    iv.extend_from_slice(&passphrase_bytes);
    iv.extend_from_slice(&salt);
    let iv_md5 = md5::compute(&iv);

    let decryptor = Aes128CbcDec::new((&key_md5.0).into(), (&iv_md5.0).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data[16..])
        .map_err(|e| format!("Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

pub fn decrypt_aes_salted_tizen(encrypted_data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    if data[0..8].to_vec() != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }

    let (header, encrypted) = data.split_at_mut(16);
    let salt = &header[8..16];
    
    let decrypted = 
    if passphrase.len() == 16 { //aes128, md5 deviration
        let iv = md5::compute(salt).0;
        Aes128CbcDec::new(passphrase.into(), (&iv).into())
            .decrypt_padded_mut::<Pkcs7>(encrypted)
            .map_err(|e| format!("Decryption error: {:?}", e))?

    } else if passphrase.len() == 32 { //aes256, sha256 deviration
        let digest: [u8; 32] = Sha256::digest(salt).into();
        let iv: [u8; 16] = digest[..16].try_into().unwrap();

        Aes256CbcDec::new(passphrase.into(), (&iv).into())
            .decrypt_padded_mut::<Pkcs7>(encrypted)
            .map_err(|e| format!("Decryption error: {:?}", e))?
            
    } else {
        return Err("Invalid passphrase lenght".into())
    };
   
    Ok(decrypted.to_vec())
}

pub fn decrypt_aes_tizen(encrypted_data: &[u8], passphrase: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encrypted = encrypted_data.to_vec();

    let decrypted = 
    if passphrase.len() == 16 { //aes128, md5 deviration
        let iv = md5::compute(salt).0;
        Aes128CbcDec::new(passphrase.into(), (&iv).into())
            .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
            .map_err(|e| format!("Decryption error: {:?}", e))?

    } else if passphrase.len() == 32 { //aes256, sha256 deviration
        let digest: [u8; 32] = Sha256::digest(salt).into();
        let iv: [u8; 16] = digest[..16].try_into().unwrap();

        Aes256CbcDec::new(passphrase.into(), (&iv).into())
            .decrypt_padded_mut::<Pkcs7>(&mut encrypted)
            .map_err(|e| format!("Decryption error: {:?}", e))?
            
    } else {
        return Err("Invalid passphrase lenght".into())
    };
   
    Ok(decrypted.to_vec())
}

pub fn is_valid_ouith(data: &[u8]) -> bool{
    return &data[256..306] == b"Tizen Software Upgrade Tree Binary Format ver. 1.8" || 
           &data[262..312] == b"Tizen Software Upgrade Tree Binary Format ver. 1.9" 
}
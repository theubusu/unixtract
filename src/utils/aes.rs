use aes::{Aes128, Aes256};

use cbc::{Decryptor, cipher::{block_padding::Pkcs7, block_padding::NoPadding, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;
pub fn decrypt_aes128_cbc_pcks7(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("UnpadError: {:?}", e))?; 
    
    Ok(decrypted.to_vec())
}
pub fn decrypt_aes128_cbc_nopad(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("UnpadError: {:?}", e))?;  //unpaderror shouldnt happen

    Ok(decrypted.to_vec())
}

type Aes256CbcDec = Decryptor<Aes256>;
pub fn decrypt_aes256_cbc_pcks7(encrypted_data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("UnpadError: {:?}", e))?; 
    
    Ok(decrypted.to_vec())
}
pub fn decrypt_aes256_cbc_nopad(encrypted_data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("UnpadError: {:?}", e))?;

    Ok(decrypted.to_vec())
}


use ecb::{Decryptor as EcbDecryptor, cipher::{KeyInit, generic_array::GenericArray}};

type Aes128EcbDec = EcbDecryptor<Aes128>;
pub fn decrypt_aes128_ecb(encrypted_data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = encrypted_data.to_vec();
    let mut decryptor = Aes128EcbDec::new(key.into());
    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }

    Ok(buffer)
}

type Aes256EcbDec = EcbDecryptor<Aes256>;
pub fn decrypt_aes256_ecb(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = encrypted_data.to_vec();
    let mut decryptor = Aes256EcbDec::new(key.into());
    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }

    Ok(buffer)
}
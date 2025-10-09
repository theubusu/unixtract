// COMMON MSD FUNCTIONS
use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;

pub fn decrypt_aes_salted_old(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    assert!(data[0..8].to_vec() == b"Salted__", "invalid encrypted data!");
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

pub fn decrypt_aes_salted_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

pub fn decrypt_aes_tizen(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>, salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    //iv = md5 of salt
    let iv = md5::compute(&salt);

    let decryptor = Aes128CbcDec::new((&(**passphrase_bytes)).into(), (&iv.0).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}
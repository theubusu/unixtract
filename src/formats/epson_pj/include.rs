use aes::cipher::block_padding::NoPadding;
use des::Des;
use cbc::Decryptor;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};

pub fn decrypt_des_cbc(encrypted_data: &[u8], key: &[u8; 8], iv: &[u8; 8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Decryptor::<Des>::new_from_slices(key, iv)?;

    let decrypted = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("UnpadError: {:?}", e))?;  //unpaderror shouldnt happen
    Ok(decrypted.to_vec())
}

use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct Entry {
    pub id: u32,
    pub offset: u32,
    pub size: u32,
    _crc32: u32,
    name_bytes: [u8; 32],
}
impl Entry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
pub struct PartitionEntry1 {
    pub magic: u32,
    pub offset: u32,
    pub size: u32,
    _info: u32,
}

#[derive(BinRead)]
pub struct PartitionHeader2 {
    _magic: u32,
    pub header_size: u32,
    pub data_size: u32,
    _pad: u32,
}

#[derive(BinRead)]
pub struct PartitionEntry2 {
    pub offset: u32,
    _info: u32,
    pub size: u32,
    _flag: u32,
}

#[derive(BinRead)]
pub struct PartitionHeader3 {
    pub pad1: u32,
    pub header_size: u32,
    pub data_size: u32,
    pub pad2: u32,
    _info_bytes: [u8; 1024],
}
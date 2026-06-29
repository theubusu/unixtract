use crate::utils::common;
use binrw::BinRead;

pub enum EncryptionType {
    HexSubst,
    AesOfb(([u8; 16], [u8; 16], String)),   //key, iv, key name
}

pub fn hex_substitute(data: &[u8], map: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| map[b as usize]).collect()
}

//for aes (new enc)
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

pub fn ver_up_decrypt_aes128ofb(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut output = Vec::with_capacity(data.len());
    let mut feedback = GenericArray::clone_from_slice(iv);
    for chunk in data.chunks(16) {
        cipher.encrypt_block(&mut feedback);
        for (b, k) in chunk.iter().zip(feedback.iter()) {
            output.push(b ^ k);
        }
    }
    output
}

pub fn is_valid_header_magic(data: &[u8]) -> bool {
    matches!(data, [b'M', b'S', b'B', d1, d2, ..] if d1.is_ascii_digit() && d2.is_ascii_digit()) ||
    matches!(data, [b'B', b'D', b'P', b'P', d1, d2, ..] if d1.is_ascii_digit() && d2.is_ascii_digit())
}

#[derive(BinRead)]
pub struct Header {
    firmware_name_bytes: [u8; 8],
    _unk_version_bytes: [u8; 8],
    firmware_version_bytes: [u8; 16],
    date_bytes: [u8; 16],
    _unk2_version_bytes: [u8; 8],
    _unk3_version_bytes: [u8; 8],
    _unk4_version_bytes: [u8; 16],
    _unk: u32,
    _checksum: u64,
    pub file_size: u32,
    _unk5_version_bytes: [u8; 16],
    _unk6_version_bytes: [u8; 16],
    _unk2: [u8; 32],
}
impl Header {
    pub fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
    pub fn firmware_version(&self) -> String {
        common::string_from_bytes(&self.firmware_version_bytes)
    }
    pub fn date(&self) -> String {
        common::string_from_bytes(&self.date_bytes)
    }
}

#[derive(BinRead)]
pub struct Entry {
    pub offset: u32,
    pub size: u32,
}
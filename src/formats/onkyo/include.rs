use crate::utils::common;
use binrw::BinRead;
use sha2::{Digest, Sha256};

#[derive(PartialEq)]
pub enum EncryptionMode {
    Old,                             //Old encryption common key
    New,                             //New encryption common network key
    NewAES(([u8; 32], [u8;16])),        //New encryption AES wrapped+ common network key
}

pub static ONKYO_MAGIC: &[u8] = b"ONKYO Encryption";
pub static NEW_MAGIC_ID: &[u8]= b"\x58\x65\x7E\x1A\xBE\x6F\x03\x09\x5F\x63\xD4\xB6\x45\xB4\x0C\x6A";

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8;16],  //ONKYO Encryption
    _header_size: u32,
    _header_checksum: u32,
    pub pack_info_offset: u32,
    pub ids_versions_offset: u32,
    pub table_offset: u32,
    _pad: [u8;12],
}

#[derive(BinRead)]
pub struct PackInfo {
    package_id_bytes: [u8;32],
    package_version_bytes: [u8;4],
    pub entry_count: u8,        //maximum number of entries that can be in the file
    pub pack_count: u8,         //how many .of* files there are
    pub pack_id: u8,            //which .of* file this is
    pub entries_in_file: u8,    //how many entries are actually in the file
}
impl PackInfo {
    pub fn package_id(&self) -> String {
        common::string_from_bytes(&self.package_id_bytes)
    }
    pub fn package_version(&self) -> String {
        common::string_from_bytes(&self.package_version_bytes)
    }
}

#[derive(BinRead)]
pub struct IDsVersionsEntry {
    pub pack_location: u8,  //in which .of* file(pack) this entry is
    id_bytes: [u8;7],
}
impl IDsVersionsEntry {
    pub fn id(&self) -> String {
        common::string_from_bytes(&self.id_bytes)
    }
}

#[derive(BinRead)]
pub struct TableEntry {
    pub size: u32,
    pub offset: u32,
    pub checksum: u32,
    _pad: [u8;4],
}

pub fn derive_aes_key(seed: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let selected = [24, 18, 7, 12, 29, 23, 12, 16].map(|i| seed[i]);
    let key = Sha256::digest(selected).into();
    let iv = [0, 31, 27, 29, 2, 15, 7, 16, 14, 9, 11, 18, 12, 8, 4, 22].map(|i| seed[i]);
    (key, iv)
}

pub fn checksum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut result = 0;
    for word in data.chunks_exact(4) {
        result = sum.wrapping_add(u32::from_le_bytes(word.try_into().unwrap()));
        sum = result.rotate_left(11);
    }
    result
}
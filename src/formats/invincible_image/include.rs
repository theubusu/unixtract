use crate::utils::common;
use binrw::BinRead;

//v3 key + iv
pub static V3_KEY: [u8; 16] = [0x32, 0xe5, 0x26, 0x1e, 0x22, 0x67, 0x5e, 0x93, 0x20, 0xcf, 0x35, 0x91, 0x7c, 0x63, 0x7a, 0x36];
pub static V3_IV:  [u8; 16] = [0xe3, 0x9f, 0x36, 0x39, 0x56, 0x9a, 0x6b, 0x8d, 0x3f, 0x2e, 0xc9, 0x44, 0xd9, 0xbc, 0xec, 0x43];

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 16],
    pub file_version: [u8; 4],
    _unk1: u32,
    ver1_bytes: [u8; 16],
    ver2_bytes: [u8; 16],
    _unk2: u16,
    _type: u8,
    pub keep_size: u32,
    _unk3: u8,
    pub data_start_offset: u32,
    pub data_size: u32,
    _data_size_2: u32,
    pub skip_size: u32,
    _unk4: u16,
    _encryption_method: u8, // 0x01 - AES128, 0x02 - AES256
    _hash_type: u8, // 0x01 - MD5, 0x02 - SHA1
    ver3_bytes: [u8; 16],
    ver4_bytes: [u8; 16],
    _unk6: [u8; 11],
    pub payload_count: u8,
}
impl Header {
    pub fn ver1(&self) -> String {
        common::string_from_bytes(&self.ver1_bytes).replace('\n', "")
    }
    pub fn ver2(&self) -> String {
        common::string_from_bytes(&self.ver2_bytes).replace('\n', "")
    }
    pub fn ver3(&self) -> String {
        common::string_from_bytes(&self.ver3_bytes).replace('\n', "")
    }
    pub fn ver4(&self) -> String {
        common::string_from_bytes(&self.ver4_bytes).replace('\n', "")
    }
}

#[derive(BinRead)]
pub struct Entry {
    name_bytes: [u8; 16],
    pub start_offset: u32,
    pub size: u32,
}
impl Entry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
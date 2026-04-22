use crate::utils::common;
use binrw::BinRead;

//v3 key + iv
pub static V3_KEY: [u8; 16] = [0x32, 0xe5, 0x26, 0x1e, 0x22, 0x67, 0x5e, 0x93, 0x20, 0xcf, 0x35, 0x91, 0x7c, 0x63, 0x7a, 0x36];
pub static V3_IV:  [u8; 16] = [0xe3, 0x9f, 0x36, 0x39, 0x56, 0x9a, 0x6b, 0x8d, 0x3f, 0x2e, 0xc9, 0x44, 0xd9, 0xbc, 0xec, 0x43];

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 16],         // INVINCIBLE_IMAGE
    pub file_infos: [u8; 8],        // 0=format version/key id, 1,2,3=unknown, 4-7=unused/reserved
    ver1_bytes: [u8; 16],           // actual firmware version
    ver2_bytes: [u8; 16],           // Netcast platform version
    _unk1: [u8; 3],
    pub chunk_size: u32,
    pub chunk_count: u8,            // 0 means not chunked
    pub data_start_offset: u32,
    pub data_size: u32,
    _file_size: u32,
    pub signature_size: u32,
    _flags: [u8; 4],                // 0,1=unknown, 2=Encryption method, 3=Hash method
    ver3_bytes: [u8; 16],           // model like in ROM filename, or sometimes just "A"?
    ver4_bytes: [u8; 16],           // LG SDK version
    _unk2: [u8; 11],
    pub payload_count: u8,          // if 0, entire data is a single payload
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
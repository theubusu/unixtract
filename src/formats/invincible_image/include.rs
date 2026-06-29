use crate::utils::common;
use binrw::BinRead;

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
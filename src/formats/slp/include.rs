use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 4],
    version_bytes: [u8; 8],
    model_bytes: [u8; 16],
    firmware_bytes: [u8; 16],
    _unk: u32,
    check: [u8; 8],
    _unk2: [u8; 8],
}
impl Header {
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    pub fn firmware(&self) -> String {
        common::string_from_bytes(&self.firmware_bytes)
    }
    pub fn is_new_type(&self) -> bool {
        &self.check == b"\x01VER_PR1"
    }
}

#[derive(BinRead)]
pub struct EntryOld {
    pub size: u32,
    pub _unk: u32,
    pub offset: u32,
    pub _unk2: u32,
}

#[derive(BinRead)]
pub struct EntryNew {
    pub size: u32,
    _unk: u32,
    pub offset: u32,
    _unk2: [u8; 12],
}
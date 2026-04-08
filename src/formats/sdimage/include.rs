use binrw::BinRead;
use crate::utils::common;

#[derive(BinRead)]
pub struct EntryHeader {
    target_name_bytes: [u8; 4],
    pub target_id: u32,
    pub model_id: u32,
    pub version: [u8; 4],
    flags: u32,
    pub size1: u32,
    pub _size2: u32,
    _info_size: u32,
    _unused: u32,
    _sha1: [u8; 20],
    #[br(count = _info_size)] info_bytes: Vec<u8>,
}
impl EntryHeader {
    pub fn target_name(&self) -> String {
        let s = common::string_from_bytes(&self.target_name_bytes);
        s.chars().rev().collect()
    }
    pub fn info(&self) -> String {
        common::string_from_bytes(&self.info_bytes)
    }

    pub fn is_encrypted(&self) -> bool {
        (self.flags & (1 << 0)) != 0
    }
    pub fn is_empty(&self) -> bool {
        (self.flags & (1 << 3)) != 0
    }
}
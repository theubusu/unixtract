use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct FileHeader {
    _magic_bytes: [u8; 6],
    pub section_count: u32
}

#[derive(BinRead)]
pub struct SectionEntry {
    pub index: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(BinRead)]
pub struct HeaderEntry {
    pub offset: u32,
    pub size: u32,
    _name_length: u8,
    #[br(count = _name_length)] name_bytes: Vec<u8>,
}
impl HeaderEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
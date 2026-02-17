use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct FileHeader {
    _magic_bytes: [u8; 6],
    _header_checksum: u32, //CRC32 of data with the size of "_header_size"
    _header_size: u64,
    pub section_count: u32,
}

#[derive(BinRead)]
pub struct SectionEntry {
    pub index: u32,
    pub offset: u64,
    pub size: u64,
}

#[derive(BinRead)]
pub struct HeaderEntry {
    pub offset: u64,
    pub size: u32,
    _name_length: u8,
    #[br(count = _name_length)] name_bytes: Vec<u8>,
}
impl HeaderEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
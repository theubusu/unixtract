use crate::utils::common;
use binrw::BinRead;

pub static TABLE_OFFSET: u64 = 0x20000;

#[derive(BinRead)]
pub struct PartTable {
    _magic_bytes: [u8;4],
    pub part_count: u8,
    #[br(count=part_count)] pub part_entries: Vec<PartEntry>,
}

#[derive(BinRead)]
pub struct PartEntry {
    name_bytes: [u8; 8],
    pub total_size: u32,
    pub used_size: u32,
    pub start: u32,         //offset
    _flags: u32,
}
impl PartEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
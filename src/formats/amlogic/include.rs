use crate::utils::common;
use binrw::{BinRead};

#[derive(BinRead)]
pub struct ImageHeader {
    _crc32: u32,
    pub version: u32,
    _magic_bytes: [u8; 4], //56 19 B5 27
    pub image_size: u64,
    pub item_align_size: u32,
    pub item_count: u32,
    _reserved: [u8; 36],
}

#[derive(BinRead)]
pub struct ItemEntry {
    _item_id: u32,
    pub file_type: u32,
    _current_offset_in_item: u64,
    pub offset_in_image: u64,
    pub item_size: u64,
    item_type_bytes: [u8; 256],
    name_bytes: [u8; 256],
    _verify: u32,
    _is_backup_item: u16,
    _backup_item_id: u16,
    _reserved: [u8; 24],
}
impl ItemEntry {
    pub fn item_type(&self) -> String {
        common::string_from_bytes(&self.item_type_bytes)
    }
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn is_sparse(&self) -> bool {
        self.file_type == 254
    }
}
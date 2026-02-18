use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct CommonHeader {
    _magic_bytes: [u8; 4],
    pub file_size: u32,
    pub pak_count: u32,
}

#[derive(BinRead)]
pub struct PakHeader {
    pak_name_bytes: [u8; 4],
    pub image_size: u32,
	platform_id_bytes: [u8; 64],
    _reserved: [u8; 56],
}
impl PakHeader {
    pub fn pak_name(&self) -> String {
        common::string_from_bytes(&self.pak_name_bytes)
    }
    pub fn platform_id(&self) -> String {
        common::string_from_bytes(&self.platform_id_bytes)
    }
}

#[derive(BinRead)]
pub struct Pak {
    pub offset : u32,
    pub size : u32,
}
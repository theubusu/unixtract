use crate::utils::common;
use binrw::BinRead;

pub static SIGNATURE_SIZE: u32 = 128;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 4], //epak
    pub file_size: u32,
	pub pak_count: u32,
	_epk2_magic: [u8; 4], //EPK2
    pub version: [u8; 4],
    ota_id_bytes: [u8; 32],
}
impl Header {
    pub fn ota_id(&self) -> String {
        common::string_from_bytes(&self.ota_id_bytes)
    }
}

#[derive(BinRead)]
pub struct PakEntry {
    pub offset: u32,
	pub size: u32,
	name_bytes: [u8; 4],
    _version: [u8; 4],
	pub segment_size: u32,
}
impl PakEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
pub struct PakHeader {
    _pak_name_bytes: [u8; 4],
    pub image_size: u32,
    platform_id_bytes: [u8; 64],
    _sw_version: u32,
    _sw_date: u32,
    _build_type: u32,
    pub segment_count: u32,
    pub segment_size: u32,
    pub segment_index: u32,
    _pak_magic_bytes: [u8; 4], //MPAK
    _reserved: [u8; 24],
    _segment_crc32: u32,
}
impl PakHeader {
    pub fn platform_id(&self) -> String {
        common::string_from_bytes(&self.platform_id_bytes)
    }
}
pub struct Pak {
    pub offset: u32,
    pub _size: u32,
    pub name: String,
}
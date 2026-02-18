use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 4],
    pub version_major: u32,
    pub version_minor: u32,
    _unused: u32,
    firmware_name_bytes: [u8; 16],
    pub data_size: u32,
    _md5_checksum: [u8; 16], //data checksum
    pub part_count: u32,
    _data_start_offset: u32,
    _signature: [u8; 128],
    _header_checksum: u32, //CRC32, calculated with the field set to 0
}
impl Header {
    pub fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
}

#[derive(BinRead)]
pub struct PartEntry {
    pub id: u32,
    pub size: u32,
    pub offset: u32,
    _md5_checksum: [u8; 16],
}
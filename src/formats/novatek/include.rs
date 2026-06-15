use binrw::BinRead;
use crate::utils::common;

#[derive(BinRead)]
pub struct NfwbHeader {
    _magic_bytes: [u8; 4],
    pub version_major: u32,
    pub version_minor: u32,
    _unused: u32,
    firmware_name_bytes: [u8; 16],
    pub data_size: u32,
    _data_checksum: [u8; 16], //MD5 checksum
    pub part_count: u32,
    _header_size: u32, //data start
    _signature: [u8; 128],
    _header_checksum: u32, //CRC32, calculated with the field set to 0
    #[br(count=part_count)] pub part_entries: Vec<NfwbPartEntry>,
}
impl NfwbHeader {
    pub fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
}

#[derive(BinRead)]
pub struct NfwbPartEntry {
    pub id: u32,
    pub size: u32,
    pub offset: u32,
    _md5_checksum: [u8; 16],
}
use crate::utils::common;
use binrw::BinRead;

#[derive(Debug, BinRead)]
pub struct TIMG {
    _magic_bytes: [u8; 4], //TIMG
    _unused1: u32,
    pub data_size: u32,
    _unused2: u32,
    _md5_checksum: [u8; 16],
    _signature: [u8; 256],
}

#[derive(Debug, BinRead)]
pub struct PIMG {
    pub magic_bytes: [u8; 4], //PIMG
    _unused1: u32,
    pub size: u32,
    _unused2: u32,
    _md5_checksum: [u8; 16],
    name_bytes: [u8; 16],
    dest_dev_bytes: [u8; 64],
    comp_type_bytes: [u8; 16],
    _unknown1: u32,
    _comment: [u8; 1024],
    _unknown2: u32,
}
impl PIMG {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn dest_dev(&self) -> String {
        common::string_from_bytes(&self.dest_dev_bytes)
    }
    pub fn comp_type(&self) -> String {
        common::string_from_bytes(&self.comp_type_bytes)
    }
}
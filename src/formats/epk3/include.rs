use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 4], //EPK3
    pub version: [u8; 4],
    ota_id_bytes: [u8; 32],
    pub package_info_size: u32,
    _bchunked: u32,
}
impl Header {
    pub fn ota_id(&self) -> String {
        common::string_from_bytes(&self.ota_id_bytes)
    }
}

#[derive(BinRead)]
pub struct HeaderNewEx {
    _pak_info_magic: [u8; 4],
    encrypt_type_bytes: [u8; 6],
    update_type_bytes: [u8; 6],
    pub update_platform_version: f32,
    pub compatible_minimum_version: f32,
    pub need_to_check_compatible_version: i32,
}
impl HeaderNewEx {
    pub fn encrypt_type(&self) -> String {
        common::string_from_bytes(&self.encrypt_type_bytes)
    }
    pub fn update_type(&self) -> String {
        common::string_from_bytes(&self.update_type_bytes)
    }
}

#[derive(BinRead)]
pub struct PkgInfoHeader {
    pub package_info_list_size: u32,
    pub package_info_count: u32,
}

#[derive(BinRead)]
pub struct PkgInfoEntry {
    _package_type: u32,
    _package_info_size: u32,
    package_name_bytes: [u8; 128],
    _package_version_bytes: [u8; 96],
    _package_architecture_bytes: [u8; 32],
    _checksum: [u8; 32],
    pub package_size: u32,
    _dipk: u32,
    //segment info
    _is_segmented: u32,
    pub segment_index: u32,
    pub segment_count: u32,
    pub segment_size: u32,
    //
    _unk: u32,
}
impl PkgInfoEntry {
    pub fn package_name(&self) -> String {
        common::string_from_bytes(&self.package_name_bytes)
    }
}

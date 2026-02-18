use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct BdlHeader {
    _magic_bytes: [u8; 4], //ibdl
    _file_version: [u8; 8],
    _unk1: u32,
    pub pkg_count: u32,
    _unk2: [u8; 12],
    date_bytes: [u8; 256],
    manufacturer_bytes: [u8; 256],
    model_bytes: [u8; 256],
    _unk3: [u8; 9],
    version_bytes: [u8; 256],
    info_bytes: [u8; 1280],
}
impl BdlHeader {
    pub fn date(&self) -> String {
        common::string_from_bytes(&self.date_bytes)
    }
    pub fn manufacturer(&self) -> String {
        common::string_from_bytes(&self.manufacturer_bytes)
    }
    pub fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn info(&self) -> String {
        common::string_from_bytes(&self.info_bytes)
    }
}

#[derive(BinRead)]
pub struct PkgListEntry {
    pub offset: u64,
    pub size: u64,
}

#[derive(BinRead)]
pub struct PkgHeader {
    _magic_bytes: [u8; 4], //ipkg
    _unk1: [u8; 12],
    pub entry_count: u32,
    _unk2: [u8; 12],
    version_bytes: [u8; 256],
    manufacturer_bytes: [u8; 256],
    name_bytes: [u8; 256],
    _unk3: [u8; 285],
}
impl PkgHeader {
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn manufacturer(&self) -> String {
        common::string_from_bytes(&self.manufacturer_bytes)
    }
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
pub struct PkgEntry {
    name_bytes: [u8; 256],
    pub offset: u64,
    pub size: u64,
    _crc32: u32,
}
impl PkgEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
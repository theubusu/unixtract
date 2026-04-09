use crate::utils::common;
use binrw::BinRead;

#[derive(PartialEq, Eq, Debug)]
pub enum SlpVariant {
    Old,
    Old2,
    New,
}

#[derive(BinRead)]
pub struct CommonMetaHeader {
    _magic_bytes: [u8; 4],
    user_version_bytes: [u8; 8],
    project_name_bytes: [u8; 16],
    firmware_version_bytes: [u8; 16],
}
impl CommonMetaHeader {
    pub fn user_version(&self) -> String {
        common::string_from_bytes(&self.user_version_bytes)
    }
    pub fn project_name(&self) -> String {
        common::string_from_bytes(&self.project_name_bytes)
    }
    pub fn firmware_version(&self) -> String {
        common::string_from_bytes(&self.firmware_version_bytes)
    }
}

#[derive(BinRead)]
pub struct MetaHeaderExtOld {
    pub snapshot_included: u8,
    pub snapshot_entry_offset: u32,
    _unuse: [u8; 15]
}

#[derive(BinRead)]
pub struct MetaHeaderExtNew {
    pub num_image: u32,
    pub snapshot_included: u8,
    snapshot_board_version_bytes: [u8; 15]
}
impl MetaHeaderExtNew {
    pub fn snapshot_board_version(&self) -> String {
        common::string_from_bytes(&self.snapshot_board_version_bytes)
    }
}

#[derive(BinRead)]
pub struct EntryCommon {
    pub size: u32,
    _crc32: u32,
    pub offset: u32,
    pub magic: u32,
}
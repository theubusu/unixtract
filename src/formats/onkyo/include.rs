use crate::utils::common;
use binrw::BinRead;

pub static ONKYO_MAGIC: &[u8] = b"ONKYO Encryption";
pub static HEADER_KEY: [u8; 8] = [0xDA, 0x57, 0x68, 0x0D, 0x44, 0x21, 0x30, 0x7A];
pub static DATA_KEY:   [u8; 8] = [0xAE, 0xB7, 0x31, 0x74, 0x47, 0xE4, 0xFB, 0x5D];

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8;16],  //ONKYO Encryption
    _header_size: u32,
    _header_checksum: u32,
    pub pack_info_offset: u32,
    pub ids_versions_offset: u32,
    pub table_offset: u32,
    _pad: [u8;12],
}

#[derive(BinRead)]
pub struct PackInfo {
    package_id_bytes: [u8;32],
    package_version_bytes: [u8;4],
    pub entry_count: u8,        //maximum number of entries that can be in the file
    pub pack_count: u8,         //how many .of* files there are
    pub pack_id: u8,            //which .of* file this is
    pub entries_in_file: u8,    //how many entries are actually in the file
}
impl PackInfo {
    pub fn package_id(&self) -> String {
        common::string_from_bytes(&self.package_id_bytes)
    }
    pub fn package_version(&self) -> String {
        common::string_from_bytes(&self.package_version_bytes)
    }
}

#[derive(BinRead)]
pub struct IDsVersionsEntry {
    pub pack_location: u8,  //in which .of* file(pack) this entry is
    id_bytes: [u8;7],
}
impl IDsVersionsEntry {
    pub fn id(&self) -> String {
        common::string_from_bytes(&self.id_bytes)
    }
}

#[derive(BinRead)]
pub struct TableEntry {
    pub size: u32,
    pub offset: u32,
    pub checksum: u32,
    _pad: [u8;4],
}
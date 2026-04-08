use binrw::BinRead;
use crate::utils::common;

#[derive(BinRead)]
pub struct IndexTableEntry {
    name_bytes: [u8; 32],
    pub offset: u32,
    pub size: u32,
    _checksum: u32,
}
impl IndexTableEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

//cmpr

#[derive(BinRead)]
pub struct CmprHeader {
    pub out_checksum: u32,
    pub count: u32,
    pub data_size: u32,
    #[br(count=count)] pub entries: Vec<CmprEntry>,
}

#[derive(BinRead)]
pub struct CmprEntry {
    pub size: u32,
    pub mode: u32,
    pub fill: u32,
}

//dumb check, since this information is not stored in header
pub fn is_cmpr(data: &[u8], size: u32) -> bool {
    if data.len() < 0x20+12 {return false};

    let count = u32::from_le_bytes(data[0x20+4..0x20+8].try_into().unwrap());
    let data_size = u32::from_le_bytes(data[0x20+8..0x20+12].try_into().unwrap());

    if count > size || data_size > size {return false};

    return (size - 0x20 - (count*12) - 12) == data_size;
}

//image rom
#[derive(BinRead)]
pub struct ImageRomHeader {
    pub count: u32,
    _unk: u32,
    _pad1: [u8; 8],
    _entry_table_sha1: [u8; 20],
    _pad2: [u8; 12],
    pub start_offset: u32,
    _pad3: [u8; 12],
    #[br(count=count)] pub entries: Vec<ImageRomEntry>,
}

#[derive(BinRead)]
pub struct ImageRomEntry {
    _decompressed_sha1: [u8; 20],
    _compressed_sha1: [u8; 20],
    _pad1: [u8; 8],
    pub offset: u32, //relative to start_offset in header
    pub size: u32,
    _pad2: [u8; 8],
}
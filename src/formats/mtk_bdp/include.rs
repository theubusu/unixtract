use crate::utils::common;
use binrw::BinRead;

pub fn find_bytes(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|window| window == pattern)
}

pub static PITIT_MAGIC: [u8; 8] = [0x69, 0x54, 0x49, 0x50, 0x69, 0x54, 0x49, 0x50];
pub static PITIT_END_MARKER: u32 = 0x69_54_49_50; //PITi - end marker of PITIT

#[derive(BinRead)]
pub struct PITITPITEntry {
	pub nand_size: u32,
    pub pit_offset: u32,
    pub pit_size: u32,
    _table_id: u32,
}

#[derive(BinRead)]
pub struct PITITBITEntry {
	pub bit_offset: u32,
    pub bit_size: u32,
    _private_data_1: u32,
    _private_data_2: u32,
}

#[derive(BinRead)]
pub struct PITHeader {
    pub pit_magic: [u8; 8],
    _version: u32,
    pub first_entry_offset: u32, //"header len"
    pub entry_size: u32, //"item lenght"
    pub entry_count: u32, //"item num"
}

pub static PIT_MAGIC: [u8; 8] = [0xDC, 0xEA, 0x30, 0x85, 0xDC, 0xEA, 0x30, 0x85];

#[derive(BinRead)]
pub struct PITEntry {
    name_bytes: [u8; 16],
    pub partition_id: u32,
    _part_info: u32,
    pub offset_on_nand: u32,
    pub size_on_nand: u32,
    _enc_size: u32,
    _no_enc_size: u32,
    _reserve: [u8; 24],
}
impl PITEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
pub struct BITEntry {
    pub partition_id: u32,
    pub offset: u32,
    pub size: u32,
    pub offset_in_target_part: u32,
    _bin_info: u32,  //"Bin info"
}

pub static BIT_MAGIC: [u8; 20] = [0xCD, 0xAB, 0x30, 0x85, 0xCD, 0xAB, 0x30, 0x85, 0xCD, 0xAB, 0x30, 0x85, 0xCD, 0xAB, 0x30, 0x85, 0xCD, 0xAB, 0x30, 0x85];
pub static BIT_END_MARKER: u32 = 0x85_30_EF_EF; //EF EF 30 85 - end marker of BIT
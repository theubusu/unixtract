use binrw::BinRead;
use crate::utils::common;

pub static DEC_KEY: u32 = 0x13641A98;

#[derive(BinRead)]
pub struct IndexTableEntry {
    name_bytes: [u8; 32],
    pub offset: u32,
    pub size: u32,
    _unk: u32,
}
impl IndexTableEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}
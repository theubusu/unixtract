use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct FwvrHeader {
    _magic_bytes: [u8; 4],      //FWVR
    pub major_ver: u32,
    pub minor_ver: u32,
    description_bytes: [u8; 500],
}
impl FwvrHeader {
    pub fn description(&self) -> String {
        common::string_from_bytes(&self.description_bytes)
    }
}
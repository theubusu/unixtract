use crate::utils::common;
use binrw::BinRead;

pub static ENTRY_MAGIC: &[u8;8] = b"\xAA\xAA\x55\x55\x55\x55\xAA\xAA";

#[derive(BinRead)]
pub struct Entry {
    pub magic: [u8; 8],     //AA AA 55 55 55 55 AA AA
    size_bytes: [u8; 8],    //hex number as string, the most efficient way to store a number in 8 bytes!
    name_bytes: [u8; 16],
}
impl Entry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn size(&self) -> usize {
        usize::from_str_radix(&common::string_from_bytes(&self.size_bytes),16).unwrap() - 32    //not including header size
    }
}
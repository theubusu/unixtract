use crate::utils::common;
use binrw::BinRead;

pub static HEADER_SIZE: usize = 0x98;

#[derive(BinRead)]
pub struct Header {
    pub vendor_magic_bytes: [u8; 4],
    _mtk_magic: [u8; 8],
    version_bytes: [u8; 68],
	pub file_size: u32,
    _flags: u32,
    product_name_bytes: [u8; 32],
    _digest: [u8; 32],
}
impl Header {
    pub fn vendor_magic(&self) -> String {
        common::string_from_bytes(&self.vendor_magic_bytes)
    }
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn product_name(&self) -> String {
        common::string_from_bytes(&self.product_name_bytes)
    }

}


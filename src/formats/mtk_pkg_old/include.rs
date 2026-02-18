use crate::utils::common;
use binrw::BinRead;

pub static KEY: u32 = 0x94102909; //09 29 10 94
// first 4 bytes of header and content are additionally XORed, they have different masks although only differ by half a byte
pub static HEADER_XOR_MASK: u32 = 0x04BE7C75; //75 7C BE 04
pub static CONTENT_XOR_MASK: u32 = 0x04BE7C72; //72 7C BE 04

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


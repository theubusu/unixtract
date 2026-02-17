use crate::utils::common;
use binrw::BinRead;

pub static HEADER_KEY: [u8; 16] = [
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
];

pub static HEADER_IV: [u8; 16] = [0x00; 16];

pub static MTK_HEADER_MAGIC: &[u8; 8] = b"#DH@FiRm";
pub static MTK_RESERVED_MAGIC: &[u8; 16] = b"reserved mtk inc";
pub static MTK_META_MAGIC: &[u8; 4] = b"iMtK";
pub static MTK_META_PAD_MAGIC: &[u8; 4] = b"iPAd";
pub static CRYPTED_HEADER_SIZE: usize = 0x30;

pub static HEADER_SIZE: usize = 0x90;

pub static PHILIPS_EXTRA_HEADER_SIZE: usize = 0x80;
pub static _PHILIPS_FOOTER_SIGNATURE_SIZE: usize = 0x100;

#[derive(BinRead)]
pub struct Header {
    pub vendor_magic_bytes: [u8; 4],
    _mtk_magic: [u8; 8], //#DH@FiRm
    version_bytes: [u8; 60],
	pub file_size: u32,
    _flags: u32,
    product_name_bytes: [u8; 32],
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

#[derive(BinRead)]
pub struct PartEntry {
    name_bytes: [u8; 4],
	pub flags: u32,
    pub size: u32,
}
impl PartEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn is_valid(&self) -> bool {
        self.name().is_ascii()
    }
    pub fn is_encrypted(&self) -> bool {
        (self.flags & 1 << 0) != 0
    }
    pub fn is_compressed(&self) -> bool { //lzhs fs
        (self.flags & 1 << 8) != 0
    }
}
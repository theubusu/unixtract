use binrw::{BinRead};

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 4], //CrAU
    pub file_format_version: u64,
    pub manifest_size: u64,
    pub metadata_signature_size: u32,
}
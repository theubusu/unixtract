use crate::utils::common;
use binrw::BinRead;

#[derive(PartialEq, Debug)]
pub enum BemFormatVersion {
    Bem10,
    Bem20
}

pub trait CSWUpgradeFileHeader {
    fn salt(&self) -> [u8; 8];
    fn original_data_lenght(&self) -> u32;
    fn encrypted_data_lenght(&self) -> u32;
    fn signature_lenght(&self) -> u32;
}

#[derive(BinRead)]
pub struct CSWUpgradeFileHeader10 {
    _magic: [u8;4],             //BEMU
    _bem_version_major: u8,
    _bem_version_minor: u8,
    _salt_string: [u8;12],      //"REL_SALTED__"
    pub salt: [u8;8],
    pub original_data_lenght: u32,
    pub encrypted_data_lenght: u32,
    pub signature_lenght: u32,
}
impl CSWUpgradeFileHeader for CSWUpgradeFileHeader10 {
    fn salt(&self) -> [u8; 8] {self.salt}
    fn original_data_lenght(&self) -> u32 {self.original_data_lenght}
    fn encrypted_data_lenght(&self) -> u32 {self.encrypted_data_lenght}
    fn signature_lenght(&self) -> u32 {self.signature_lenght}
}

#[derive(BinRead)]
pub struct CSWUpgradeFileHeader20 {
    _magic: [u8;4],             //BEMU
    _bem_version_major: u8,
    _bem_version_minor: u8,
    _header_size: u32,
    _salt_string: [u8;12],      //"REL_SALTED__"
    pub salt: [u8;8],
    _file_size: u32,
    _reserved: [u8; 128],
    pub original_data_lenght: u32,
    pub encrypted_data_lenght: u32,
    pub signature_lenght: u32,
}
impl CSWUpgradeFileHeader for CSWUpgradeFileHeader20 {
    fn salt(&self) -> [u8; 8] {self.salt}
    fn original_data_lenght(&self) -> u32 {self.original_data_lenght}
    fn encrypted_data_lenght(&self) -> u32 {self.encrypted_data_lenght}
    fn signature_lenght(&self) -> u32 {self.signature_lenght}
}

#[derive(BinRead)]
pub struct CSWUpgradeDataBlock {
    _image_name_lenght: u32,
    #[br(count = _image_name_lenght)] image_name_bytes: Vec<u8>,
    pub block_number: u32,
    pub total_blocks: u32,
    pub encrypted_data_lenght: u32,
    pub original_data_lenght: u32,
    pub signature_lenght: u32,
}
impl CSWUpgradeDataBlock {
    pub fn image_name(&self) -> String {
        common::string_from_bytes(&self.image_name_bytes)
    }
}
use crate::utils::common;
use binrw::BinRead;

#[derive(PartialEq, Eq, Debug)]
pub enum PkgFormatVer {
    PkgVer30,
    PkgVer40
}

#[derive(Debug, BinRead)]
pub struct TIMGHeader {
    _sign: [u8; 4],             //TIMG
    _pkg_format_ver: [u8; 8],   //PKGVER40
    pub flen: u32,              //data size
    _md5sum: [u8; 16],
    _rsa_sign: [u8; 256],
}

#[derive(Debug, BinRead)]
pub struct PIMG {
    pub sign: [u8; 4],          //PIMG
    pub flen: u32,              //data size
    _md5sum: [u8; 16],
    img_name_bytes: [u8; 16],
    dev_path_bytes: [u8; 32],
    compress_bytes: [u8; 16],
    _dev_ofs: u32,
    txt_param_bytes: [u8; 1024],
    _dev_type: u32,
}
impl PIMG{
    pub fn img_name(&self) -> String {
        common::string_from_bytes(&self.img_name_bytes)
    }
    pub fn dev_path(&self) -> String {
        common::string_from_bytes(&self.dev_path_bytes)
    }
    pub fn comp_type(&self) -> String {
        common::string_from_bytes(&self.compress_bytes)
    }
    pub fn txt_param(&self) -> String {
        common::string_from_bytes(&self.txt_param_bytes)
    }
}

#[derive(Debug, BinRead)]
pub struct PPHeader {
    pub sign: [u8; 4],      //PPCH
    _crc32: u32,
}

#[derive(Debug, BinRead)]
pub struct PPEntry {
    name_bytes: [u8; 16],
    dev_path_bytes: [u8; 32],
    pub offset: u32,
    pub valid: u32,
    _index: u32,
}
impl PPEntry{
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn dev_path(&self) -> String {
        common::string_from_bytes(&self.dev_path_bytes)
    }
}
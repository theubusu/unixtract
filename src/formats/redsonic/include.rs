use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct RedsonicHeader { //0x100
    _magic: [u8; 8],        //REDSONIC
    _unk: u32,
    pub version_info_bytes: [u8; 52],

    pub has_bootloader: u32,
    pub has_kernel: u32,
    pub has_rootfs: u32,
    pub has_para0: u32,

    pub bootloader_size: u32,
    pub kernel_size: u32,
    pub rootfs_size: u32,
    pub para0_size: u32,

    _clean_config: u32,
    _crc32: u32,

    //ಠ_ಠ
    pub has_splash: u32,
    pub splash_size: u32,

}
impl RedsonicHeader {
    pub fn version_info(&self) -> String {
        common::string_from_bytes(&self.version_info_bytes)
    }
}
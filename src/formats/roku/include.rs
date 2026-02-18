use binrw::BinRead;

pub static FILE_KEY: [u8; 16] = [
        0x2A, 0x54, 0xA5, 0x30, 0xE0, 0x09, 0xA3, 0xDC,
        0x03, 0xFB, 0xC3, 0x5E, 0x23, 0xA2, 0xC1, 0x0D,
];

pub static FILE_IV: [u8; 16] = [0x00; 16];

#[derive(BinRead)]
pub struct ImageHeader {
    _empty: [u8; 8],
    _magic_bytes: [u8; 8], //imgARMcC
    _target_bytes: [u8; 4],
    _platform_id: [u8; 4],
    pub image_type: u32,
    pub size1: u32,
    _size2: u32,
    pub data_start_offset: u32,
    _data_link_address: u32,
    _data_entry_point_offset: u32,
    pub flags: u32,
    _timestamp: u32,
    _build_host: [u8; 4],
    _unk: [u8; 4],
    _rest_of_header: [u8; 192],
}
impl ImageHeader {
    pub fn is_encrypted(&self) -> bool {
        self.flags == 0x80
    }
    pub fn type_string(&self) -> &str {
        if self.image_type == 0xa {
            return "initfs"
        } else if self.image_type == 0x18 {
            return "uImage"
        } else if self.image_type == 0x3 {
            return "loader"
        } else if self.image_type == 0xd {
            return "app_cramfs"
        } else if self.image_type == 0x6 {
            return "Customization Package"
        } else if self.image_type == 0xe {
            return "firmware_blob"
        } else {
            return "unknown"
        }
    }
}
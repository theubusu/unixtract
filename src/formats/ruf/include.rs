use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct RufHeader {
    _magic_bytes: [u8; 6],
    _upgrade_type_bytes: [u8; 2],
	_unk1: u32,
    date_time_bytes: [u8; 32],
    buyer_bytes: [u8; 8],
    model_bytes: [u8; 32],
    region_info_bytes: [u8; 32],
    pub version_bytes: [u8; 4],
    pub data_size: u32,
    _unk2: [u8; 20],
    pub dual_ruf_flag: u32,
    _unk3: [u8; 44],
    pub payload_count: u16,
    _payload_entry_size: u16,
    pub payloads_start_offset: u32,
}
impl RufHeader {
    pub fn date_time(&self) -> String {
        common::string_from_bytes(&self.date_time_bytes)
    }
    pub fn buyer(&self) -> String {
        common::string_from_bytes(&self.buyer_bytes)
    }
    pub fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    pub fn region_info(&self) -> String {
        common::string_from_bytes(&self.region_info_bytes)
    }
    pub fn is_dual_ruf(&self) -> bool {
        if self.dual_ruf_flag == 0x44 {true} else {false}
    }
}

#[derive(BinRead)]
pub struct RufEntry {
    _metadata: [u8; 32],
    pub payload_type_bytes: u32,
	pub size: u32,
    _unk1: u32,
    _unk2: [u8; 20],
}
impl RufEntry {
    pub fn payload_type(&self) -> &str {
        if self.payload_type_bytes == 1 {
            return "squashfs"
        } else if self.payload_type_bytes == 2 {
            return "cfe"
        } else if self.payload_type_bytes == 3 {
            return "vmlinuz"
        } else if self.payload_type_bytes == 4 {
            return "loader"
        } else if self.payload_type_bytes == 5 {
            return "splash"
        } else {
            return "unknown"
        }
    }
}
use crate::utils::common::{string_from_bytes};
use binrw::BinRead;
use crate::formats::sddl_sec::include::AesKeyEntry;

//These keys seem to be the same for most models
pub const KEYS: [AesKeyEntry; 2] = [
    //from tbl_sdboot;0, Decrypted with AES
    AesKeyEntry {
        key: [0x2e, 0x2a, 0x33, 0x62, 0x33, 0xe5, 0x5a, 0xba, 0xf5, 0xff, 0xec, 0x54, 0xf8, 0xab, 0x71, 0x25 ],
        iv:  [0x2c, 0xa4, 0xb4, 0x7a, 0xff, 0xcb, 0x1a, 0xe8, 0xe1, 0xea, 0x2d, 0x9e, 0xf5, 0x12, 0x62, 0x9a]
    },

    //from tbl_sdboot;1, Decrypted with AES
    AesKeyEntry {
        key: [0x24, 0x5e, 0x8d, 0xe8, 0xf4, 0x99, 0xb0, 0xf9, 0x6e, 0xc1, 0x55, 0xb6, 0x08, 0xe2, 0x42, 0xf3],
        iv:  [0x3e, 0x8f, 0x29, 0xd4, 0xba, 0xe7, 0x76, 0xa5, 0x18, 0xa7, 0xb6, 0x3c, 0x42, 0xca, 0x1b, 0x43]
    }
];

#[derive(Debug, BinRead)]
pub struct SdbootSecHeader {
    num_files_str_bytes: [u8; 4],
    key_id_str_bytes: [u8; 4],
    _unused: [u8; 24],
}

impl SdbootSecHeader {
    pub fn num_files(&self) -> u32 {
        let string = string_from_bytes(&self.num_files_str_bytes);
        string.parse().unwrap()
    }
    pub fn key_id(&self) -> u16 {
        let string = string_from_bytes(&self.key_id_str_bytes);
        string.parse().unwrap()
    }
}

pub struct FileEntry {
    pub name: String,
    pub size: usize,
    pub offset: u64,
}

#[derive(Debug, BinRead)]
pub struct SdbootEntryHeader {
    file_name_bytes: [u8; 0x34],
    file_size_str_bytes: [u8; 0xc],
}
impl SdbootEntryHeader {
    pub fn name(&self) -> String {
        string_from_bytes(&self.file_name_bytes)
    }
    pub fn file_size(&self) -> usize {
        let string = string_from_bytes(&self.file_size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct EntrySubHeader {
    size_str_bytes: [u8; 0xc],
    _unused: [u8; 20],
}
impl EntrySubHeader {
    pub fn size(&self) -> usize {
        let string = string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct InfoListHeader {
    pub part_count: u16,
    _unk1: u32,
    _unk2: u32,
    _unk3: u32,
    _unk4: u16,
}

#[derive(Debug, BinRead)]
pub struct InfoListEntry {
    _crc: u32,
    pub out_size: u32,
    _stored_size: u32,
    pub compressed_flag: u8,
    pub ciphered_flag: u8,
    _unused: u16,
}
impl InfoListEntry {
    pub fn is_compressed(&self) -> bool {
        self.compressed_flag == 0x01
    }
    pub fn is_ciphered(&self) -> bool {
        self.ciphered_flag == 0x01
    }
}
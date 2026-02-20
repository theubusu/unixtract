use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 6],
    pub entry_count: u16,
    pub file_size: u32,
}

#[derive(BinRead)]
pub struct Entry {
    pub entry_type: u16,
    pub entry_size: u32,
    _unk_flag: u8,
    pub encryption_flag: u8,
}

//based on this check in firmware: [A-Z][A-Z][A-Z]-[0-1][A-Z][A-Z][A-Z]_\\x\\x\\x_\\x\\0\\0
//the check needs to be this extensive since the cipher is so weak and keys can be similar, leading to correct looking string even with incorrect key.
pub fn is_valid_ver_string(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| {
        matches!(b,
            b'A'..=b'Z' |
            b'0'..=b'9' |
            b'-' | 
            b'_' |
            b'\x00'
        )
    })
}
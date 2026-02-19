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
use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
	_magic_bytes: [u8; 4],
	_unk1: u32,
    _unk2: u16,
    _flags: u8,
    _unk3: u8,
    _header_size: u16,
    _hash_size: u16,
    pub file_size: u64,
    pub entry_count: u16,
    _hash_count: u16,
    _unk4: u32,
}

#[derive(BinRead, Clone)]
pub struct Entry {
    pub flags: u32,
    _unk1: u32,
    pub offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}
impl Entry {
    pub fn id(&self) -> u32 {
        self.flags >> 20
    }
    pub fn is_compressed(&self) -> bool {
        (self.flags & 8) != 0
    }
    pub fn is_blocked(&self) -> bool {
        (self.flags & 0x800) != 0
    }
    pub fn is_block_table(&self) -> bool {
        (self.flags & 1) != 0
    }
}

#[derive(BinRead, Clone)]
pub struct BlockEntry {
    pub offset: u32,
    pub size: u32,
}
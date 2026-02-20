use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 6],
    pub entries: [BodyHeader; 8],
    _unk: u16,
    _data_checksum: u32,
    _unk2: u32,
}

#[derive(BinRead)]
pub struct BodyHeader {
    pub body_type: u16,
    pub size: u32,
}
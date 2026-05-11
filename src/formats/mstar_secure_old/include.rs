use binrw::BinRead;

pub static MSTAR_DEFAULT_UPGRADE_KEY: [u8; 16] = [0x00, 0x07, 0xff, 0x41, 0x54, 0x53, 0x4d, 0x92, 0xfc, 0x55, 0xaa, 0x0f, 0xff, 0x01, 0x10, 0xe0];
pub static CHUNK_ID:  &[u8; 8] = b"MSTAR...";
pub static CHUNK_END: &[u8; 8] = b"...mstar";

#[derive(BinRead)]
pub struct ChunkFileFooter {
    _chunk_id: [u8; 8],
    pub segment_size: u32,
    pub file_data_offset: u32,
    pub file_data_len: u32,
    _file_hash_offset: u32,
    _file_hash_len: u32,
    _file_signature_offset: u32,
    _file_signature_len: u32,
    _reserved: [u8; 84],
    _chunk_end: [u8; 8],
}
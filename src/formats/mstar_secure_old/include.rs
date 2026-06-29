use binrw::BinRead;

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
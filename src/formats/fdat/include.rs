use sha1::{Sha1, Digest};
use binrw::BinRead;

pub enum EncryptionMode {
    Sha(ShaCrypter),                    //1st gen (sha cipher[mutable])
    AesEcb([u8; 16]),                   //2nd gen (key)
    DoubleAesEcb(([u8;16], [u8;16])),   //3rd gen ((key1, key2))
    AesCbc(([u8; 32], [u8;16])),        //4th gen ((key, iv[mutable]))
}

pub static COMMON_AES_KEY: [u8;16] = [0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24];
pub static CXD90014_AES_KEY: [u8;16] = [0xE8, 0xB0, 0x88, 0x6D, 0x97, 0x18, 0x4F, 0x1F, 0x65, 0xC7, 0x67, 0xF7, 0x93, 0x99, 0x65, 0xBF];
pub static CXD90045_AES_KEY: [u8;32] = [0xC1, 0xAA, 0x8F, 0x7C, 0x46, 0x34, 0x1F, 0xFE, 0xD1, 0x55, 0x89, 0xFC, 0x81, 0x70, 0xA6, 0xBB, 0x59, 0x25, 0xE8, 0x5F, 0x62, 0x82, 0xD7, 0xF9, 0x5B, 0xA3, 0xFD, 0xF5, 0xD3, 0x03, 0xE0, 0x6B];

pub fn calc_sum(data: &[u8]) -> u16 {
    data.chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
        .fold(0u16, |acc, x| acc.wrapping_add(x))
}

//custom sha decryptor class (need to keep digest status between decryptions)
pub struct ShaCrypter {
    key: [u8; 40],
    digest: [u8; 20],
}
impl ShaCrypter {
    pub fn new(key: [u8; 40]) -> Self {
        Self {
            key,
            digest: key[..20].try_into().unwrap(),
        }
    }

    pub fn decrypt_block(&mut self, data: &[u8]) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(data.len());

        while keystream.len() < data.len() {
            let mut hasher = Sha1::new();
            hasher.update(&self.digest);
            hasher.update(&self.key[20..40]);
            self.digest = hasher.finalize().into();
            keystream.extend_from_slice(&self.digest);
        }

        data.iter()
            .zip(keystream.iter())
            .map(|(d, k)| d ^ k)
            .collect()
    }
}

#[derive(BinRead)]
pub struct FdatHeader {
    _magic: [u8; 8],        // "UDTRFIRM"
    _header_checksum: u32,  //crc32 from here to header enc    
    _version: [u8;4],       // "0100"
    pub mode_type: u8,      //U=user, O=verskip, M=minor, P=prod
    _pad1: [u8; 3],
    _luw_flag: u8,          //N=normal
    _pad2: [u8; 11],
    pub version_minor: u8,
    pub version_major: u8,
    _pad3: [u8; 2],
    pub model: u32,
    pub region: u32,
    _pad4: [u8; 4],
    pub firmware_offset: u32,
    pub firmware_size: u32,
    pub num_filesystems: u32,
    _pad5: [u8; 4],
    #[br(count = num_filesystems)] pub filesystem_entries: Vec<FdatFileSystemHeader>,
}

#[derive(BinRead)]
pub struct FdatFileSystemHeader {
    pub mode_type: u8,  //U=user, P=prod
    _pad1: [u8;3],
    pub offset: u32,
    pub size: u32,
    _pad2: [u8; 4],
}
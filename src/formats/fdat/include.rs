use sha1::{Sha1, Digest};
use binrw::BinRead;

pub enum EncryptionMode {
    Sha(ShaCrypter),                    //1st gen (sha cipher[mutable])
    AesEcb([u8; 16]),                   //2nd gen (key)
    DoubleAesEcb(([u8;16], [u8;16])),   //3rd gen ((key1, key2))
    AesCbc(([u8; 32], [u8;16])),        //4th gen ((key, iv[mutable]))
}

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
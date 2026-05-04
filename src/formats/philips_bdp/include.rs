use crate::utils::common;
use binrw::BinRead;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

pub static KEY1: [u8; 32] = [
    0x01, 0x06, 0x18, 0x00, 0x0a, 0x22, 0x02, 0x41, 0x4d, 0x41, 0x08, 0x22, 0x12, 0x09, 0x04, 0x20, 
    0x22, 0x12, 0x02, 0x11, 0x01, 0x05, 0x41, 0x00, 0x05, 0x22, 0x22, 0x0a, 0x24, 0x08, 0x40, 0x24
];

pub static IV1: [u8; 16] = [
    0x58, 0x87, 0x40, 0x13, 0x20, 0x00, 0x01, 0x30, 0x03, 0x58, 0x81, 0x42, 0x04, 0x22, 0x9c, 0x01
];

//AES 256 CFB with IV reset every 0x80 bytes
pub fn bebin_decrypt_aes256cfb(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(data.len());

    for chunk in data.chunks(0x80) {
        let mut state = *iv;

        for block in chunk.chunks(16) {
            let mut ks = state.into();
            cipher.encrypt_block(&mut ks);

            let pt: Vec<u8> = block.iter()
                .zip(ks.iter())
                .map(|(&c, &k)| c ^ k)
                .collect();

            let n = block.len();
            state[..n].copy_from_slice(block);

            out.extend_from_slice(&pt);
        }
    }

    out
}

#[derive(PartialEq, Debug)]
pub enum HeaderType {
    Old,
    New
}

pub trait UpgHeader {
    fn _magic_num(&self) -> [u8; 7];
    fn name(&self) -> String;
    fn target_num(&self) -> u8;
    fn version(&self) -> String;
    fn target_size(&self) -> u32;
    fn _target_verify(&self) -> u32;
    fn entries(&self) -> &[UpgEntry];
}

#[derive(BinRead)]
pub struct UpgHeaderOld {
    _magic_num: [u8; 7],    //PHILIPS
    target_name_bytes: [u8; 8],
    pub target_num: u8,
    target_version_bytes: [u8; 8],
    pub target_size: u32,
    _target_verify: u32,    //checksum
    #[br(count=target_num)] pub entries: Vec<UpgEntry>,
}
impl UpgHeader for UpgHeaderOld {
    fn _magic_num(&self) -> [u8; 7] {
        self._magic_num
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.target_name_bytes)
    }
    fn target_num(&self) -> u8 {
        self.target_num
    }
    fn version(&self) -> String {
        common::string_from_bytes(&self.target_version_bytes)
    }
    fn target_size(&self) -> u32 {
        self.target_size
    }
    fn _target_verify(&self) -> u32 {
        self._target_verify
    }
    fn entries(&self) -> &[UpgEntry] {
        &self.entries
    }
}

#[derive(BinRead)]
pub struct UpgHeaderNew {
    _magic_num: [u8; 7],    //PHILIPS
    target_name_bytes: [u8; 12],
    pub target_num: u8,
    target_version_bytes: [u8; 8],
    pub target_size: u32,
    _target_verify: u32,    //checksum
    #[br(count=target_num)] pub entries: Vec<UpgEntry>,
}
impl UpgHeader for UpgHeaderNew {
    fn _magic_num(&self) -> [u8; 7] {
        self._magic_num
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.target_name_bytes)
    }
    fn target_num(&self) -> u8 {
        self.target_num
    }
    fn version(&self) -> String {
        common::string_from_bytes(&self.target_version_bytes)
    }
    fn target_size(&self) -> u32 {
        self.target_size
    }
    fn _target_verify(&self) -> u32 {
        self._target_verify
    }
    fn entries(&self) -> &[UpgEntry] {
        &self.entries
    }
}

#[derive(BinRead)]
pub struct UpgEntry {
    pub id: u8,
    pub iic: u8,
    version_bytes: [u8; 4],
    pub offset: u32,
    pub size: u32,
}
impl UpgEntry {
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
}
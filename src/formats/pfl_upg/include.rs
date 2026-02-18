use crate::utils::common;
use binrw::BinRead;
use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

pub static AUTO_FWS: &[(&str, &str)] = &[
    ("Q5551", "q5551"),
    ("Q5553", "q5551"),
    ("Q554E", "q5551"),
    ("Q554M", "q5551"),
    ("QF1EU", "qf1eu"),
    ("QF2EU", "qf1eu"),
    ("Q591E", "q591e"),
    ("Q522E", "q522e"),
    ("Q582E", "q522e"),
    ("Q5481", "q5481"),
    ("Q5431", "q5431"),
    ("Q5492", "q5492"),
    ("S5551", "q5551"), //Sharp
];

type Aes256EcbDec = Decryptor<Aes256>;

pub fn decrypt_aes256_ecb(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_array: [u8; 32] = key.try_into()?;

    let mut decryptor = Aes256EcbDec::new(&key_array.into());
    let mut buffer = ciphertext.to_vec();

    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    
    Ok(buffer)
}

#[derive(BinRead)]
pub struct Header {
    _magic_bytes: [u8; 8],
    pub header_size: u32,
    pub data_size: u32,
	_crc32: u32,
	pub mask: u32,
	_data_size_decompressed: u32,
	_padding2: u32,
	description_bytes: [u8; 512],
}
impl Header {
    pub fn description(&self) -> String {
        common::string_from_bytes(&self.description_bytes).replace('\r', "\n")
    }
    pub fn is_encrypted(&self) -> bool {
        (self.mask & 0x2000_0000) != 0
    }
}

#[derive(BinRead)]
pub struct FileHeader {
    file_name_bytes: [u8; 60],
    pub real_size: u32,
	pub stored_size: u32,
	pub header_size: u32,
    pub attributes: [u8; 4],
}
impl FileHeader {
    pub fn file_name(&self) -> String {
        common::string_from_bytes(&self.file_name_bytes)
    }
    pub fn is_folder(&self) -> bool {
        (self.attributes[3] & (1 << 1)) != 0
    }
    pub fn has_extended_name(&self) -> bool {
        (self.attributes[2] & (1 << 7)) != 0
    }
    pub fn _is_package(&self) -> bool {
        (self.attributes[3] & (1 << 1)) != 0
    }
}
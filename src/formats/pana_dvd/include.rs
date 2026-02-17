use crate::utils::common;
use binrw::BinRead;
use super::pana_dvd_crypto::{decrypt_data};
use crate::utils::aes::{decrypt_aes128_cbc_nopad};

pub fn find_key<'a>(key_array: &'a [&'a str], data: &[u8], expected_magic: &[u8], magic_offset: usize) -> Result<Option<[u8; 8]>, Box<dyn std::error::Error>> {
    for key_hex in key_array {
        let key_bytes = hex::decode(key_hex)?;
        let key_array: [u8; 8] = key_bytes.as_slice().try_into()?;
        let decrypted = decrypt_data(data, &key_array);
     
        if decrypted[magic_offset..].starts_with(expected_magic) {
            return Ok(Some(key_array));
        }
    }
    Ok(None)
}

pub fn find_aes_key_pair<'a>(key_array: &'a [(&'a str, &'a str, &'a str)], data: &[u8], expected_magic: &[u8], magic_offset: usize) -> Result<Option<([u8; 16], [u8; 16], [u8; 8])>, Box<dyn std::error::Error>> {
    for (aes_key_hex, aes_iv_hex, cust_key_hex) in key_array {
        let aes_key: [u8; 16] = hex::decode(aes_key_hex)?.as_slice().try_into()?;
        let aes_iv: [u8; 16] = hex::decode(aes_iv_hex)?.as_slice().try_into()?;
        let aes_decrypted = decrypt_aes128_cbc_nopad(data, &aes_key, &aes_iv)?;

        let key_bytes = hex::decode(cust_key_hex)?;
        let key_array: [u8; 8] = key_bytes.as_slice().try_into()?;
        let decrypted = decrypt_data(&aes_decrypted, &key_array);
     
        if decrypted[magic_offset..].starts_with(expected_magic) {
            return Ok(Some((aes_key, aes_iv, key_array)));
        }
    }
    Ok(None)
}

pub static MAX_HEADER_SIZE: usize = 0x2000;

#[derive(BinRead)]
pub struct AesHeaderFileEntry {
    pub offset: u32,
    pub size: u32,
}

pub struct FileEntry {
    pub offset: u32,
    pub base_offset: u32,
}

//checksums are mostly Adler32, but some very old files use Checksum32 instead.

#[derive(BinRead)]
pub struct ModuleEntry {
    #[br(count = 4)] pub name_bytes: Vec<u8>,
    version_bytes: [u8; 4],
    _unk: u32,
    pub offset: u32,
    platform_bytes: [u8; 8],
    _unk1: u16,
    id_bytes: [u8; 6],
    pub size: u32,
    pub data_checksum: u32, //checksum of the entrys' DATA
    _unk2: u32,
    _entry_checksum: u32, //checksum of THIS header entry (all previous 44 bytes)
}
impl ModuleEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn platform(&self) -> String {
        common::string_from_bytes(&self.platform_bytes)
    }
    pub fn id(&self) -> String {
        common::string_from_bytes(&self.id_bytes)
    }
    pub fn is_valid(&self) -> bool {
        self.name().is_ascii() && self.platform().is_ascii()
    }
}

#[derive(BinRead)]
pub struct MainListHeader {
    _checksum: u32, //checksum of the MAIN LIST
    _unk: u32, //seems to be always 1?
    pub list_size: u32,
    pub decompressed_part_size: u32,
    _unk2: u32,
}
impl MainListHeader {
    pub fn entry_count(&self) -> u32 {
        (&self.list_size - 20) / 8
    }
}

#[derive(BinRead)]
pub struct MainListEntry {
    pub size: u32,
    pub checksum: u32, //checksum of this MAIN entrys' data
}

pub const COMPRESSED_FILE_MAGIC: &[u8; 8] = b"EXTRHEAD";

#[derive(BinRead)]
pub struct CompressedFileHeader {
    _header_string: [u8; 14], //EXTRHEADDRV \x01\x00
    pub compression_type_byte: u16,
    pub decompressed_size: u32,
    _destination_address: u32,
    pub compressed_size: u32,
    _unk: u32,
    _footer_offset: u32,
    _base_address: u32,
    _checksum: u32, //unknown type of checksum
    _checksum_flag: u8,
    _unused: [u8; 19],
}
impl CompressedFileHeader {
    pub fn compression_type(&self) -> &str {
        if self.compression_type_byte == 0 {
            return "Uncompressed"
        } else if self.compression_type_byte == 1 {
            return "GZIP"
        } else if self.compression_type_byte == 2 {
            return "LZSS"
        } else {
            return "Unknown"
        }
    }
}


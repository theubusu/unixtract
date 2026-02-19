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
    _magic_bytes: [u8; 8],      // EXTRHEAD
    _unk_string: [u8; 4],       // DRV\x20 ?
    _compressed_flag: u16,      // checks for 1 here, else -> "Error! Not compress"
    pub compression_type: u16,  // 0 - not compressed, 1 - GZIP , 2 - LZSS
    pub dest_size: u32,         // decompressed size
    _dest_address: u32,
    pub src_size: u32,          // compressed size
    _src_address: u32,
    _footer_offset: u32,        // offset to EXTRFOOT
    _unk: u32,
    _checksum: u32,             // adler32 calculated every checksum_skip bytes of decompressed data
    _checksum_skip: u32,
    _unused: [u8; 16],
}
impl CompressedFileHeader {
    pub fn compression_type_str(&self) -> &str {
        if self.compression_type == 0 {
            return "Uncompressed"
        } else if self.compression_type == 1 {
            return "GZIP"
        } else if self.compression_type == 2 {
            return "LZSS"
        } else {
            return "Unknown"
        }
    }
}


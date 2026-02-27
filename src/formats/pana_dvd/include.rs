use crate::utils::common;
use binrw::{BinRead, BinWrite};
use super::pana_dvd_crypto::{decrypt_data};
use crate::utils::aes::{decrypt_aes128_cbc_nopad};

//find key

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

// --

#[derive(BinRead)]
pub struct AesHeaderFileEntry {
    pub offset: u32,
    pub size: u32,
}

pub struct FileEntry {
    pub offset: u32,
    pub size: u32,
    pub header_size: u32,
}

//checksums are mostly Adler32, but some very old files use Checksum32 instead.

pub static LIST_SIZE: usize = 0x1800;

#[derive(BinRead, BinWrite)]
pub struct ModuleEntry {
    name_bytes: [u8; 4],
    version_bytes: [u8; 4],
    _unk: u32,
    pub offset: u32,
    model_id_bytes: [u8; 8],
    pub _oem_id: u8,                //0x4D = Panasonic
    pub _force_update_flag: u8,     //if not 0x00, force the update and also "Scheduling Format HDD"
    id_bytes: [u8; 6],
    pub size: u32,
    pub data_checksum: u32,         //checksum of the entrys' DATA
    pub _flags: [u8; 4],            //last byte denotes compression type in some firmwares, see CompressionType
    pub _entry_checksum: u32,       //checksum of THIS header entry (all previous 44 bytes)
}
impl ModuleEntry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    pub fn model_id(&self) -> String {
        common::string_from_bytes(&self.model_id_bytes)
    }
    pub fn id(&self) -> String {
        common::string_from_bytes(&self.id_bytes)
    }
    pub fn is_valid(&self) -> bool {
        self.name().is_ascii() && self.model_id().is_ascii()
    }
}

#[derive(BinRead)]
pub struct MainListHeader {
    pub _checksum: u32,                 //checksum of whole list excluding this field
    _unk: u32,                          //seems to be always 1
    pub list_size: u32,                 //size of the entire list, including the entries AND this header
    pub decompressed_part_size: u32,    
    pub _compression_type: u32,         //see CompressionType
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
    _unk_string: [u8; 4],       // "DRV " ?
    pub _compressed_flag: u16,  // checks for 1 here, else -> "Error! Not compress"
    pub compression_type: u16,  // see CompressionType. GzipAndLzss is not used in this context.
    pub dest_size: u32,         // decompressed size
    pub _dest_address: u32,
    pub src_size: u32,          // compressed size
    pub _src_address: u32,
    pub _footer_offset: u32,    // offset to footer, with magic bytes "EXTRFOOT". it aligns data to 8 bytes for encryption.
    _unk: u32,
    pub _checksum: u32,         // adler32 calculated every checksum_skip bytes of decompressed data
    pub _checksum_skip: u32,
    _unused: [u8; 16],
}

#[derive(Debug, PartialEq)]
pub enum CompressionType {
    None,
    Gzip,
    Lzss,
    GzipAndLzss,
    Unknown,
}
impl From<u16> for CompressionType {
    fn from(value: u16) -> Self {
        match value {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::Lzss,
            3 => CompressionType::GzipAndLzss,
            _ => CompressionType::Unknown
        }
    }
}

#[derive(BinRead)]
pub struct DriveHeader {
    manufacturer_bytes: [u8; 8],
    model_bytes: [u8; 16],
    version_bytes: [u8; 7],
    _unk: u8,
}
impl DriveHeader {
    pub fn manufacturer(&self) -> String {
        common::string_from_bytes(&self.manufacturer_bytes)
    }
    pub fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    pub fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
}
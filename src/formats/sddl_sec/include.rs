//base: sddl_dec 7.0 https://github.com/theubusu/sddl_dec
use binrw::{BinRead};
use aes::{cipher::block_padding::NoPadding};
use cbc::{Decryptor, cipher::{BlockDecryptMut, KeyIvInit}};
use des::{TdesEde3};

use crate::utils::common::{string_from_bytes};
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes128_cbc_pcks7};

pub fn decipher(s: &[u8]) -> Vec<u8> {
    let len_ = s.len();
    let mut v3: u32 = 904;
    let mut out = s.to_vec();
    let mut cnt = 0;
    
    if len_ > 0 {
        let true_len = if len_ >= 0x80 {
            128
        } else {
            len_
        };
        
        if true_len > 0 {
            let mut i = 0;
            let mut j: u8 = 0;
            
            while i < s.len() {
                let iter_ = s[i];
                i += 1;
                j = j.wrapping_add(1);
                
                let v11 = (iter_ as u32).wrapping_add(38400) & 0xffffffff;
                let v12 = iter_ ^ ((v3 & 0xff00) >> 8) as u8;
                v3 = v3.wrapping_add(v11).wrapping_add(163) & 0xffffffff;
                
                if j == 0 {
                    v3 = 904;
                }
                
                if cnt < out.len() {
                    out[cnt] = v12;
                    cnt += 1;
                }
            }
        }
    }
    
    out
}

pub fn decrypt_3des(encrypted_data: &[u8], key_entry: &DesKeyEntry) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Decryptor::<TdesEde3>::new_from_slices(&key_entry.key, &key_entry.iv).unwrap();

    let out_data = decryptor.decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;

    Ok(out_data.to_vec())
}
pub enum KeyEntry {
    DES(DesKeyEntry),
    AES(AesKeyEntry),
    AESPcks7(AesKeyEntry)
}
impl KeyEntry {
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self {
            KeyEntry::DES(k) => decrypt_3des(data, &k),
            KeyEntry::AES(k) => decrypt_aes128_cbc_nopad(data, &k.key, &k.iv),
            KeyEntry::AESPcks7(k) => decrypt_aes128_cbc_pcks7(data, &k.key, &k.iv)
        }
    }
}

#[derive(Copy, Clone)]
pub struct AesKeyEntry {
    pub key: [u8; 16],
    pub iv: [u8; 16],
}

pub struct DesKeyEntry {
    pub key: [u8; 24],
    pub iv: [u8; 8],
}

//new type (2011+) always has this key, it is decipher()'ed from /usr/local/customer_dl/crypto_key
pub const NEW_KEY: AesKeyEntry = AesKeyEntry {
    key: [0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB, 0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C],
    iv:  [0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54, 0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66],
};

//for old (pre-2011), can have multiple keys either AES or 3DES
//these keys are stored in key tables with id 0 and 1 (this is what key_id in secfile hdr should decide, but it seems to be always 0), and are decrypted using the master DES key:
//c2a421f6adeb44be b0fda68c234bb3c5 e98ec68c326fd395 07c8d75ef1b1b142
//There are 3 known key tables - tbl2009 (From 2009 dlget), tbl2010 (From 2010 dlget) and tbl_sdboot (From bootloader)
//the decrypted key is then used as AES or DES key for the contents
pub const OLD_KEYS_AES: [AesKeyEntry; 2] = [
    //from tbl2009;0, Decrypted with DES
    //2009/ some 2010
    AesKeyEntry {
        key: [0xe5, 0x80, 0x3d, 0x1c, 0x23, 0x51, 0x16, 0xa4, 0xd0, 0xbc, 0x94, 0xad, 0x08, 0x92, 0xab, 0x29],
        iv:  [0x26, 0x70, 0xe0, 0xf8, 0x0e, 0x2f, 0x8c, 0xef, 0xf8, 0x3e, 0xd9, 0x94, 0x8a, 0xf8, 0x34, 0xfd],
    },

    //from tbl_sdboot;0, Decrypted with DES
    //2009/2010 Japan
    AesKeyEntry {
        key: [0xa2, 0x76, 0xd3, 0x75, 0x75, 0x02, 0x4a, 0xec, 0x52, 0x38, 0x3d, 0x97, 0x20, 0x8c, 0xc1, 0x7a],
        iv:  [0x16, 0xa8, 0xf1, 0xef, 0xec, 0x26, 0x6e, 0x26, 0xd3, 0x79, 0x51, 0xa8, 0x1a, 0xdc, 0xf4, 0x0b],
    }
];

pub const OLD_KEYS_DES: [DesKeyEntry; 2] = [
    //from tbl2010;0, Decrypted with DES
    //2010
    DesKeyEntry {
        key: [0x46, 0xd0, 0x26, 0x61, 0x0b, 0xc2, 0x9d, 0x32, 0x57, 0x16, 0x16, 0x92, 0x3b, 0xae, 0xc4, 0xc8, 0x0e, 0x91, 0xf2, 0xe9, 0x8a, 0xef, 0x02, 0x62],
        iv:  [0x64, 0x3d, 0x0e, 0xa7, 0x3b, 0xa1, 0x19, 0x02],
    },

    //from tbl_sdboot;0, Decrypted with DES
    //before 2009
    DesKeyEntry {
        key: [0xa2, 0x76, 0xd3, 0x75, 0x75, 0x02, 0x4a, 0xec, 0x52, 0x38, 0x3d, 0x97, 0x20, 0x8c, 0xc1, 0x7a, 0x16, 0xa8, 0xf1, 0xef, 0xec, 0x26, 0x6e, 0x26],
        iv:  [0xd3, 0x79, 0x51, 0xa8, 0x1a, 0xdc, 0xf4, 0x0b]
    },
];

// -- STRUCTURES --
// -- SECFILE --

pub static DOWNLOAD_ID: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[derive(Debug, BinRead)]
pub struct SecHeader {
    pub _download_id: [u8; 4],      //always 0x11, 0x22, 0x33, 0x44 - magic?
    key_id_str_bytes: [u8; 4],    //"key_id", purpose unknown
    grp_num_str_bytes: [u8; 4],    //"grp_num", the count of groups, also represents the count of info files because each group has a respective info file
    prg_num_str_bytes: [u8; 4],    //"prg_num", the count of module (.FXX) files
    _unused_or_reserved: [u8; 16], //not used, is zeros
}
impl SecHeader {
    pub fn key_id(&self) -> u32 {
        let string = string_from_bytes(&self.key_id_str_bytes);
        string.parse().unwrap()
    }
    pub fn grp_num(&self) -> u32 {
        let string = string_from_bytes(&self.grp_num_str_bytes);
        string.parse().unwrap()
    }
    pub fn prg_num(&self) -> u32 {
        let string = string_from_bytes(&self.prg_num_str_bytes);
        string.parse().unwrap()
    }
}

pub static INFO_FILE_EXTENSION: &str = ".TXT";

#[derive(Debug, BinRead)]
pub struct FileHeader {
    name_str_bytes: [u8; 12],
    size_str_bytes: [u8; 12],
}
impl FileHeader {
    pub fn name(&self) -> String {
        string_from_bytes(&self.name_str_bytes)
    }
    pub fn size(&self) -> u64 {
        let string = string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

// -- MODULE --
#[derive(Debug, BinRead)]
pub struct ModuleComHeader { //"com_header"
    pub _download_id: [u8; 4],      //always 0x11, 0x22, 0x33, 0x44 - magic?
    _outer_maker_id: u8,
    _outer_model_id: u8,
    _inner_maker_id: u8,
    _reserve1: u8,
    _reserve2: u32,
    _reserve3: u32,
    _start_version: [u8; 4],    //the first version that can upgrade to the new version
    _end_version: [u8; 4],      //the last version that can upgrade to the new version
    _new_version: [u8; 4],      //the new version, as in the version of the data in this module
    _reserve4: u16,
    _module_num: u16,          //the logic seems to indicate that there can be multiple entries in one module, but i have never seen this go above 1.
}

#[derive(Debug, BinRead)]
pub struct ModuleHeader { //"header", appears after com_header
    _module_id: u16,
    module_atr: u8,
    _target_id: u8,
    pub cmp_size: u32,
    _org_size: u32,
    _crc_value: u32,   
}
impl ModuleHeader {
    pub fn is_ciphered(&self) -> bool {
        (self.module_atr & 0x02) != 0
    }
    pub fn is_compressed(&self) -> bool {
        (self.module_atr & 0x01) != 0
    }
}

#[derive(Debug, BinRead)]
pub struct ContentHeader {
    _magic1: u8,    //always 0x01?
    _dest_offset: u32,
    _source_offset: u32,
    pub size: u32,
    _magic2: u8,    //always 0x21?
}
impl ContentHeader {
    //these hacks are needed because for some reason older files have the first nibble of the offset set to D/C
    //no idea why, but masking them off makes it works properly
    pub fn dest_offset(&self) -> u32 {
        if ((self._dest_offset >> 28) & 0xF) == 0xD {
            self._dest_offset & 0x0FFFFFFF 
        } else {
            self._dest_offset
        }
    }
    pub fn source_offset(&self) -> u32 {
        if ((self._source_offset >> 28) & 0xF) == 0xC {
            self._source_offset & 0x0FFFFFFF 
        } else {
            self._source_offset
        }
    }
    pub fn has_subfile(&self) -> bool {
        self.source_offset() == 0x10E
    }
}

// -- TDI --
// Called SDIT.FDI in the secfile

pub static TDI_FILENAME: &str = "SDIT.FDI";
pub static SUPPORTED_TDI_VERSION: u16 = 2;

#[derive(Debug, BinRead)]
pub struct TdiHead {
    pub download_id: [u8; 4],      //always 0x11, 0x22, 0x33, 0x44 - magic?
    pub num_of_group: u8,
    _reserve1: u8,
    pub format_version: u16,       //checks for "2" here
}

#[derive(Debug, BinRead)]
pub struct TdiGroupHead {
    pub group_id: u8,
    pub num_of_target: u8,         //logic checks that this is not more than 5
    _reserved: u16,
}

#[derive(Debug, BinRead)]
pub struct TdiTgtInf {
    _outer_maker_id: u8,
    _outer_model_id: u8,
    _inner_maker_id: u8,
    _reserve3: u8,
    _inner_model_id: [u8; 4],
    _ext_model_id: [u8; 4],
    pub _start_version: [u8; 4],    //the first version that can upgrade to the new version
    pub _end_version: [u8; 4],      //the last version that can upgrade to the new version
    pub new_version: [u8; 4],       //the new version, as in the version of the data in this module
    pub target_id: u8,
    _num_of_compatible_target: u8,
    pub num_of_txx: u16,            //"TXX" refers to the ".FXX" segment files of each module. I assume F is an encrypted version of T, the same happens with SDIT; "TDI" -> "FDI"
    _module_path: [u8; 8],
    module_name_bytes: [u8; 8],
}
impl TdiTgtInf {
    pub fn module_name(&self) -> String {
        string_from_bytes(&self.module_name_bytes)
    }
    pub fn version_string(&self) -> String {
        format!("{}.{}{}{}", self.new_version[0], self.new_version[1], self.new_version[2], self.new_version[3])
    }
}
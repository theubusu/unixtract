//sddl_dec 6.0 https://github.com/theubusu/sddl_dec
use crate::utils::common;
use binrw::BinRead;

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
        let string = common::string_from_bytes(&self.key_id_str_bytes);
        string.parse().unwrap()
    }
    pub fn grp_num(&self) -> u32 {
        let string = common::string_from_bytes(&self.grp_num_str_bytes);
        string.parse().unwrap()
    }
    pub fn prg_num(&self) -> u32 {
        let string = common::string_from_bytes(&self.prg_num_str_bytes);
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
        common::string_from_bytes(&self.name_str_bytes)
    }
    pub fn size(&self) -> u64 {
        let string = common::string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

// -- MODULE --
#[derive(Debug, BinRead)]
pub struct ModuleComHeader { //"com_header"
    pub download_id: [u8; 4],      //always 0x11, 0x22, 0x33, 0x44 - magic?
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
    _unknown: [u8; 8],
    module_name_bytes: [u8; 8],
}
impl TdiTgtInf {
    pub fn module_name(&self) -> String {
        common::string_from_bytes(&self.module_name_bytes)
    }
    pub fn version_string(&self) -> String {
        format!("{}.{}{}{}", self.new_version[0], self.new_version[1], self.new_version[2], self.new_version[3])
    }
}

// -- dec key --
pub static DEC_KEY: [u8; 16] = [
    0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
    0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
];
    
pub static DEC_IV: [u8; 16] = [
    0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
    0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
];
//sddl_dec 6.0
use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "sddl_sec", detector_func: is_sddl_sec_file, extractor_func: extract_sddl_sec }
}

use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};
use crate::utils::compression::{decompress_zlib};

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
static DEC_KEY: [u8; 16] = [
    0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
    0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
];
    
static DEC_IV: [u8; 16] = [
    0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
    0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
];

pub fn is_sddl_sec_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 32).expect("Failed to read from file.");
    let deciph_header = decipher(&header);
    if deciph_header.starts_with(b"\x11\x22\x33\x44") {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

fn get_sec_file(mut file: &File) -> Result<(FileHeader, Vec<u8>), Box<dyn std::error::Error>> {
    let mut hdr_reader = Cursor::new(decrypt_aes128_cbc_pcks7(&common::read_exact(&mut file, 32)?, &DEC_KEY, &DEC_IV)?);
    let file_header: FileHeader = hdr_reader.read_be()?;
    let file_data = decrypt_aes128_cbc_pcks7(&common::read_exact(&mut file, file_header.size() as usize)?, &DEC_KEY, &DEC_IV)?;

    Ok((file_header, file_data))
}

fn parse_tdi_to_modules(tdi_data: Vec<u8>) -> Result<Vec<TdiTgtInf>, Box<dyn std::error::Error>> {
    let mut tdi_reader = Cursor::new(tdi_data);
    let tdi_header: TdiHead = tdi_reader.read_be()?;
    if tdi_header.download_id != DOWNLOAD_ID {
        return Err("Invalid TDI header!".into());
    }
    if tdi_header.format_version != SUPPORTED_TDI_VERSION {
        return Err(format!("Unsupported TDI format version {}! (The supported version is {})", tdi_header.format_version, SUPPORTED_TDI_VERSION).into());
    }

    println!("[TDI] Group count: {}", tdi_header.num_of_group);
    let mut modules: Vec<TdiTgtInf> = Vec::new();

    for _i in 0..tdi_header.num_of_group {
        let group_head: TdiGroupHead = tdi_reader.read_be()?;
        println!("[TDI] Group ID: {}, Target count: {}", group_head.group_id, group_head.num_of_target);

        for _i in 0..group_head.num_of_target {
            let tgt_inf: TdiTgtInf = tdi_reader.read_be()?;
            println!("[TDI] - {}, Target ID: {}, Segment count: {}, Version: {}",
                    tgt_inf.module_name(), tgt_inf.target_id, tgt_inf.num_of_txx, tgt_inf.version_string());

            //push unique modules
            if !modules.iter().any(|m| m.module_name() == tgt_inf.module_name()) {
                modules.push(tgt_inf);
            }
        }
    }

    Ok(modules)
}

pub fn extract_sddl_sec(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    file.seek(SeekFrom::Start(0))?;
    let mut secfile_hdr_reader = Cursor::new(decipher(&common::read_exact(&mut file, 32)?));
    let secfile_header: SecHeader = secfile_hdr_reader.read_be()?;

    println!("File info -\nKey ID: {}\nGroup count: {}\nModule file count: {}\n", secfile_header.key_id(), secfile_header.grp_num(), secfile_header.prg_num());
    fs::create_dir_all(&app_ctx.output_dir)?;

    let (tdi_file, tdi_data) = get_sec_file(&file)?;
    println!("[TDI] Name: {}, Size: {}", tdi_file.name(), tdi_file.size());
    //if save_extra { //Save SDIT
    //    let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&output_folder).join(tdi_file.name()))?;
    //    out_file.write_all(&tdi_data)?;
    //}
    if tdi_file.name() != TDI_FILENAME {
        return Err(format!("Invalid TDI filename {}!, expected: {}", tdi_file.name(), TDI_FILENAME).into());
    }
    //parse TDI
    let modules = parse_tdi_to_modules(tdi_data)?;

    //get info files, each info file belongs to its respecitve group in the TDI
    for i in 0..secfile_header.grp_num() {
        let (info_file, info_data) = get_sec_file(&file)?;
        println!("\n[INFO] ID: {}, Name: {}, Size: {}", i, info_file.name(), info_file.size());
        if !info_file.name().ends_with(INFO_FILE_EXTENSION) {
            return Err(format!("Info file {} does not have the expected extension {}!", info_file.name(), INFO_FILE_EXTENSION).into());
        }
        //if save_extra { //Save info file
        //    let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&output_folder).join(info_file.name()))?;
        //    out_file.write_all(&info_data)?;
        //}
        //print info file
        println!("{}", String::from_utf8_lossy(&info_data));
    }

    //parse module data
    for (i, module) in modules.iter().enumerate(){
        println!("\nModule #{}/{} - {}, Target ID: {}, Segment count: {}, Version: {}", 
                i+1, &modules.len(), module.module_name(), module.target_id, module.num_of_txx, module.version_string());

        for i in 0..module.num_of_txx {
            let (module_file, module_data) = get_sec_file(&file)?;
            if !module_file.name().starts_with(&module.module_name()) {
                return Err(format!("Module file {} does not start with the module's name: {}!", module_file.name(), module.module_name()).into());
            }    
            println!("  Segment #{}/{} - Name: {}, Size: {}", i+1, module.num_of_txx, module_file.name(), module_file.size());

            let mut module_reader = Cursor::new(module_data);
            let com_header: ModuleComHeader = module_reader.read_be()?;
            if com_header.download_id != DOWNLOAD_ID {
                return Err("Invalid module com_header!".into());
            }

            let module_header: ModuleHeader = module_reader.read_be()?;
            let mut module_data = common::read_exact(&mut module_reader, module_header.cmp_size as usize)?;
            if module_header.is_ciphered() {
                println!("      - Deciphering...");
                module_data = decipher(&module_data);
            }
            if module_header.is_compressed() {
                println!("      - Decompressing...");
                module_data = decompress_zlib(&module_data)?;
            }

            let mut content_reader = Cursor::new(module_data);
            let content_header: ContentHeader = content_reader.read_be()?;
            println!("      --> 0x{:X} @ 0x{:X}", content_header.size, content_header.dest_offset());
            
            let output_path: PathBuf;
            if content_header.has_subfile() {
                let sub_filename_bytes = common::read_exact(&mut content_reader, 0x100)?;
                let sub_filename = common::string_from_bytes(&sub_filename_bytes);
                println!("      --> {}", sub_filename);

                let sub_folder_path = Path::new(&app_ctx.output_dir).join(module.module_name());
                fs::create_dir_all(&sub_folder_path)?;
                output_path = Path::new(&sub_folder_path).join(sub_filename);

            } else {
                output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", module.module_name()));
            }

            let data = common::read_exact(&mut content_reader, content_header.size as usize)?;
            let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
            out_file.seek(SeekFrom::Start(content_header.dest_offset() as u64))?;
            out_file.write_all(&data)?;

        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
//sddl_dec 5.0
use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "sddl_sec", detector_func: is_sddl_sec_file, extractor_func: extract_sddl_sec }
}

use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};
use crate::utils::compression::{decompress_zlib};

#[derive(BinRead)]
struct SddlSecHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //0x11, 0x22, 0x33, 0x44
    #[br(count = 4)] _unused: Vec<u8>,
    #[br(count = 4)] info_entries_count_str_bytes: Vec<u8>,
    #[br(count = 4)] module_entries_count_str_bytes: Vec<u8>,
    #[br(count = 16)] _unk: Vec<u8>,
}
impl SddlSecHeader {
    fn info_entry_count(&self) -> u32 {
        let string = common::string_from_bytes(&self.info_entries_count_str_bytes);
        string.parse().unwrap()
    }
    fn module_entries_count(&self) -> u32 {
        let string = common::string_from_bytes(&self.module_entries_count_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(BinRead)]
struct EntryHeader {
    #[br(count = 12)] name_str_bytes: Vec<u8>,
    #[br(count = 12)] size_str_bytes: Vec<u8>,
}
impl EntryHeader {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_str_bytes)
    }
    fn size(&self) -> u64 {
        let string = common::string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(BinRead)]
struct ModuleHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //0x11, 0x22, 0x33, 0x44
    _unk1: u8,
    _id: u8,
    #[br(count = 10)] _unused: Vec<u8>,
    #[br(count = 4)] _file_base_version: Vec<u8>,
    #[br(count = 4)] _file_previous_version: Vec<u8>,
    #[br(count = 4)] file_version: Vec<u8>,
    #[br(count = 4)] _unused2: Vec<u8>,
    _index: u16,
    #[br(count = 2)] control_bytes: Vec<u8>,
    compressed_data_size: u32,
    _uncompressed_data_size: u32,
    _checksum: u32,
}
impl ModuleHeader {
    fn is_compressed(&self) -> bool {
        self.control_bytes[0] == 0x3
    }
}

#[derive(BinRead)]
struct ContentHeader {
    _magic1: u8,
    #[br(count = 4)] dest_offset_bytes: Vec<u8>,
    #[br(count = 4)] source_offset_bytes: Vec<u8>,
    size: u32,
    _magic2: u8,
}
impl ContentHeader {
    fn dest_offset(&self) -> u32 {
        let first_byte;
        if self.dest_offset_bytes[0] & 0xF0 == 0xD0 {
            first_byte = self.dest_offset_bytes[0] & 0x0F;
        } else {
            first_byte = self.dest_offset_bytes[0];
        }
        u32::from_be_bytes([first_byte, self.dest_offset_bytes[1], self.dest_offset_bytes[2], self.dest_offset_bytes[3]])
    }
    fn source_offset(&self) -> u32 {
        u32::from_be_bytes([0x00, self.source_offset_bytes[1], self.source_offset_bytes[2], self.source_offset_bytes[3]])
    }
}

static DEC_KEY: [u8; 16] = [
    0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
    0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
];
    
static DEC_IV: [u8; 16] = [
    0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
    0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
];

pub fn is_sddl_sec_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let header = common::read_file(app_ctx.file, 0, 32)?;
    let deciph_header = decipher(&header);
    if deciph_header.starts_with(b"\x11\x22\x33\x44") {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

//ported from original from https://nese.team/posts/justctf/
fn decipher(s: &[u8]) -> Vec<u8> {
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

pub fn extract_sddl_sec(app_ctx: &AppContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file;
    let mut hdr_reader = Cursor::new(decipher(&common::read_exact(&mut file, 32)?));
    let hdr: SddlSecHeader = hdr_reader.read_be()?;

    //SDIT.FDI + info files + module files
    let total_entry_count = 1 + hdr.info_entry_count() + hdr.module_entries_count();
    println!("File info:\nInfo entry count: {}\nModule entry count: {}\nTotal entry count: {}",
            hdr.info_entry_count(), hdr.module_entries_count(), total_entry_count);

    for i in 0..total_entry_count {
        let mut entry_header_reader = Cursor::new(decrypt_aes128_cbc_pcks7(&common::read_exact(&mut file, 32)?, &DEC_KEY, &DEC_IV)?);
        let entry_header: EntryHeader = entry_header_reader.read_be()?;

        println!("\n({}/{}) - {}, Size: {}", i + 1, total_entry_count, entry_header.name(), entry_header.size());

        let data = common::read_exact(&mut file, entry_header.size() as usize)?;
        let dec_data = decrypt_aes128_cbc_pcks7(&data, &DEC_KEY, &DEC_IV)?;

        fs::create_dir_all(app_ctx.output_dir)?;
        //detect the file type based on the counts of each file
        if i == 0 { //SDIT.FDI file
            let output_path = Path::new(app_ctx.output_dir).join(entry_header.name());
            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            out_file.write_all(&dec_data)?;
            println!("-- Saved file!");

        } else if i - 1 < hdr.info_entry_count() { //.TXT info file
            println!("{}", String::from_utf8_lossy(&dec_data));
            continue

        } else { //Module file
            let name = entry_header.name();
            let source_name = name.split(".").next().unwrap();

            let mut module_reader = Cursor::new(dec_data);
            let module_header: ModuleHeader = module_reader.read_be()?;
            println!("- Version: {}.{}{}{}", module_header.file_version[0], module_header.file_version[1], module_header.file_version[2], module_header.file_version[3]);

            let module_data = common::read_exact(&mut module_reader, module_header.compressed_data_size as usize)?;
            println!("- Deciphering...");
            let deciphered_data = decipher(&module_data);

            let content: Vec<u8>;
            if module_header.is_compressed() {
                println!("-- Decompressing...");
                content = decompress_zlib(&deciphered_data)?;
            } else {
                println!("-- Uncompressed...");
                content = deciphered_data;
            }

            let mut content_reader = Cursor::new(content);
            let content_header: ContentHeader = content_reader.read_be()?;

            let output_path: PathBuf; 
            if content_header.source_offset() == 270 {
                let file_name_bytes = common::read_exact(&mut content_reader, 256)?;
                let file_name = common::string_from_bytes(&file_name_bytes);
                println!("--- File name: {}", file_name);

                let out_folder_path = Path::new(app_ctx.output_dir).join(source_name);
                fs::create_dir_all(&out_folder_path)?;
                output_path = Path::new(&out_folder_path).join(file_name);
            } else {
                output_path = Path::new(app_ctx.output_dir).join(format!("{}.bin", source_name));
            }

            let data = common::read_exact(&mut content_reader, content_header.size as usize)?;

            let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
            out_file.seek(SeekFrom::Start(content_header.dest_offset() as u64))?;
            out_file.write_all(&data)?;
            println!("--- Saved!");

        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
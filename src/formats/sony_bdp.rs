use std::any::Any;
use crate::{InputTarget, AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "sony_bdp", detector_func: is_sony_bdp_file, extractor_func: extract_sony_bdp }
}

use std::fs::File;
use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::formats;

//thx sony
static HEX_SUBSTITUTION: [u8; 256] = [
	0xE8, 0x4D, 0x63, 0xF4, 0xF8, 0xA9, 0x21, 0x9C, 0xC7, 0x82, 0xCD, 0xE3, 0xC1, 0xCE, 0xC0, 0xFA, 0xE7, 0xD6, 0x96, 0x46, 0x12, 0x03, 0x14, 0x33, 0xED, 0x10, 0xEC, 0x69, 0x16, 0xE0, 0x28, 0x30, 
	0x77, 0x0E, 0x3D, 0xEF, 0x36, 0x4C, 0x18, 0xEB, 0x41, 0x89, 0x64, 0x8A, 0x70, 0x0C, 0x23, 0xA3, 0x79, 0x6D, 0x75, 0x7E, 0x1A, 0x2D, 0x01, 0x91, 0x88, 0xCB, 0xFC, 0x8B, 0xFD, 0x94, 0x0A, 0x39, 
	0xBC, 0x98, 0x87, 0xBB, 0xC2, 0x9B, 0x81, 0x1C, 0x4B, 0xA6, 0x58, 0x59, 0x45, 0x57, 0x8C, 0x7B, 0x5A, 0x56, 0x08, 0x73, 0x65, 0xEE, 0x2A, 0x25, 0xB0, 0x5B, 0x55, 0xB2, 0xB8, 0x1E, 0xEA, 0xC5, 
	0x6A, 0x40, 0x86, 0x5C, 0x3C, 0x54, 0xBF, 0xF6, 0xA8, 0xF2, 0x06, 0x4A, 0xFE, 0xC4, 0x32, 0x8D, 0xF0, 0x5D, 0x35, 0x53, 0xD7, 0xBD, 0xBA, 0x20, 0x2F, 0xCA, 0xE1, 0xCC, 0xA4, 0x44, 0x85, 0xDE, 
	0xDB, 0x5E, 0x27, 0x52, 0x6E, 0x38, 0x04, 0x66, 0xD0, 0x92, 0xD3, 0xC6, 0x7D, 0x71, 0xDA, 0x2C, 0x9A, 0x49, 0x8E, 0x80, 0x13, 0x5F, 0x11, 0x51, 0x15, 0x22, 0xCF, 0xAC, 0x0F, 0xD5, 0xFF, 0x3F, 
	0x17, 0xAD, 0xD8, 0xD9, 0xAB, 0x02, 0x6B, 0x0D, 0xDF, 0xF1, 0x84, 0x3B, 0x78, 0x19, 0x76, 0x60, 0x50, 0xDC, 0xC3, 0xB5, 0x43, 0x0B, 0x95, 0x97, 0x67, 0xD4, 0x29, 0xF7, 0xE4, 0x1B, 0xAE, 0x48, 
	0xB1, 0x8F, 0x24, 0x7A, 0x74, 0xFB, 0x34, 0x09, 0x00, 0x31, 0x9F, 0x61, 0x4F, 0xB6, 0xA0, 0xA7, 0xB4, 0x9E, 0x1D, 0xAA, 0xF9, 0xBE, 0x37, 0x2E, 0xB9, 0x6F, 0xA5, 0x83, 0xA1, 0x93, 0x07, 0xE2, 
	0x7F, 0x3E, 0xF3, 0x99, 0x62, 0x4E, 0xE9, 0xC8, 0x6C, 0x68, 0x1F, 0x47, 0x42, 0x26, 0x9D, 0xE5, 0x7C, 0x72, 0x3A, 0x2B, 0xE6, 0xF5, 0xD2, 0x90, 0x05, 0xD1, 0xDD, 0xC9, 0xAF, 0xB7, 0xA2, 0xB3,
];

fn hex_substitute(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| HEX_SUBSTITUTION[b as usize]).collect()
}

#[derive(BinRead)]
struct Header {
    #[br(count = 8)] firmware_name_bytes: Vec<u8>,
    #[br(count = 8)] _unk_version_bytes: Vec<u8>,
    #[br(count = 16)] firmware_version_bytes: Vec<u8>,
    #[br(count = 16)] date_bytes: Vec<u8>,
    #[br(count = 8)] _unk2_version_bytes: Vec<u8>,
    #[br(count = 8)] _unk3_version_bytes: Vec<u8>,
    #[br(count = 16)] _unk4_version_bytes: Vec<u8>,
    _unk: u32,
    _checksum: u64,
    file_size: u32,
    #[br(count = 16)] _unk5_version_bytes: Vec<u8>,
    #[br(count = 16)] _unk6_version_bytes: Vec<u8>,
    #[br(count = 32)] _unk2: Vec<u8>,
}
impl Header {
    fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
    fn firmware_version(&self) -> String {
        common::string_from_bytes(&self.firmware_version_bytes)
    }
    fn date(&self) -> String {
        common::string_from_bytes(&self.date_bytes)
    }
}

#[derive(BinRead)]
struct Entry {
    offset: u32,
    size: u32,
}

pub fn is_sony_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"\x01\x73\xEC\xC9" || header == b"\x01\x73\xEC\x1F" || header == b"\xEC\x7D\xB0\xB0" { //MSB1x, MSB0x, BDPPxx
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_sony_bdp(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let obf_header = common::read_exact(&mut file, 300)?;
    let header = hex_substitute(&obf_header);
    let mut hdr_reader = Cursor::new(header);
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFirmware: {}\nVersion: {}\nDate: {}\nFile size: {}", 
            hdr.firmware_name(), hdr.firmware_version(), hdr.date(), hdr.file_size);

    let mut last_file_path: Option<PathBuf> = None;
    let mut first_entry_offset = 0;
    let mut i = 1;
    loop {
        if (i != 1) && (hdr_reader.position() >= first_entry_offset) {
            break
        }

        let entry: Entry = hdr_reader.read_le()?;
        if entry.size == 0 {
            continue
        }

        println!("\n#{} - Offset: {}, Size: {}", i, entry.offset, entry.size);
        if i == 1 {
            first_entry_offset = entry.offset as u64;
        }

        let obf_data = common::read_file(&file, entry.offset as u64, entry.size as usize)?;
        let data = hex_substitute(&obf_data);

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i));
        last_file_path = Some(output_path.clone());

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;          
        out_file.write_all(&data)?;

        println!("- Saved file!");
        i += 1;
    }

    //The last file is often a Mtk BDP file so we can extract that here.
    if last_file_path.is_some() {
        println!("\nChecking if it's also MTK BDP...");

        let last_file = File::open(last_file_path.unwrap())?;
        let mtk_extraction_path = app_ctx.output_dir.join(format!("{}", i + 1));
        let ctx: AppContext = AppContext { input: InputTarget::File(last_file), output_dir: mtk_extraction_path };

        if let Some(result) = formats::mtk_bdp::is_mtk_bdp_file(&ctx)? {
            println!("- MTK BDP file detected!\n");
            
            formats::mtk_bdp::extract_mtk_bdp(&ctx, result)?;
        } else {
            println!("- Not an MTK BDP file.");    
        }
    }

    println!("\nExtraction finished!");
     
    Ok(())
}
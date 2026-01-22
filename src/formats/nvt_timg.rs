use std::str;
use std::path::{Path};
use std::io::{Seek, Write};
use std::fs::{self, File, OpenOptions};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::compression::{decompress_gzip};
use crate::utils::sparse::{unsparse_to_file};

#[derive(Debug, BinRead)]
struct TIMG {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //TIMG
    _unused1: u32,
    data_size: u32,
    _unused2: u32,
    #[br(count = 16)] _md5_checksum: Vec<u8>,
    #[br(count = 256)] _signature: Vec<u8>,
}

#[derive(Debug, BinRead)]
struct PIMG {
    #[br(count = 4)] magic_bytes: Vec<u8>, //PIMG
    _unused1: u32,
    size: u32,
    _unused2: u32,
    #[br(count = 16)] _md5_checksum: Vec<u8>,
    #[br(count = 16)] name_bytes: Vec<u8>,
    #[br(count = 64)] dest_dev_bytes: Vec<u8>,
    #[br(count = 16)] comp_type_bytes: Vec<u8>,
    _unknown1: u32,
    #[br(count = 1024)] _comment: Vec<u8>,
    _unknown2: u32,
}
impl PIMG {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn dest_dev(&self) -> String {
        common::string_from_bytes(&self.dest_dev_bytes)
    }
    fn comp_type(&self) -> String {
        common::string_from_bytes(&self.comp_type_bytes)
    }
}

pub fn is_nvt_timg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"TIMG" {
        true
    } else {
        false
    }
}

pub fn extract_nvt_timg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();
    let timg: TIMG = file.read_le()?;
    println!("File info:\nData size: {}", timg.data_size);

    let mut pimg_i = 0;
    while file.stream_position()? < file_size as u64 {
        pimg_i += 1;
        let pimg: PIMG = file.read_le()?;
        if pimg.magic_bytes != b"PIMG" {
            println!("Invalid PIMG magic!");
            return Ok(());
        }

        let data = common::read_exact(&mut file, pimg.size as usize)?;

        println!("\n#{} - {}, Size: {}, Dest: {}, Compression: {}", pimg_i, pimg.name(), pimg.size, pimg.dest_dev(), pimg.comp_type());

        let out_data;
        let output_path = Path::new(&output_folder).join(pimg.name() + ".bin");

        if pimg.comp_type() == "gzip" && data.starts_with(b"\x1F\x8B") { //additionally check for gzip header, because sometimes its deceptive
            println!("- Decompressing gzip...");
            out_data = decompress_gzip(&data)?;
        } else if pimg.comp_type() == "none" || pimg.comp_type() == "" {
            out_data = data;
        } else if pimg.comp_type() == "sparse" {
            println!("- Unsparsing...");
            unsparse_to_file(&data, output_path)?;
            println!("-- Saved file!");
            continue
        } else {
            println!("- Warning: unsupported compression type!");
            out_data = data;
        }

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&out_data)?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
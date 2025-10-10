use std::str;
use std::path::{Path};
use std::io::{Read, Write};
use std::fs::{self, File, OpenOptions};

use binrw::{BinRead, BinReaderExt};
use flate2::read::GzDecoder;

use crate::common;

#[derive(Debug, BinRead)]
struct PIMG {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    _unknown1: u32,
    size: u32,
    _unknown2: u32,
    #[br(count = 16)] _checksum: Vec<u8>,
    #[br(count = 16)] name_bytes: Vec<u8>,
    #[br(count = 64)] dest_dev_bytes: Vec<u8>,
    #[br(count = 16)] comp_type_bytes: Vec<u8>,
    #[br(count = 1032)] _comment: Vec<u8>,
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

pub fn is_tpv_timg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"TIMG" {
        true
    } else {
        false
    }
}

fn decompress_gzip(compressed_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

pub fn extract_tpv_timg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _timg = common::read_exact(&mut file, 288)?; //TIMG magic + header

    loop {
        let pimg = match file.read_le::<PIMG>() {
            Ok(val) => val,
            Err(_) => break, // EOF
        };
        let data = common::read_exact(&mut file, pimg.size as usize)?;

        println!("\nPIMG: Name: {}, Size: {}, Dest: {}, Compression: {}", pimg.name(), pimg.size, pimg.dest_dev(), pimg.comp_type());

        let out_data;

        if pimg.comp_type() == "gzip" {
            println!("- Decompressing gzip...");
            out_data = decompress_gzip(&data)?;
        } else if pimg.comp_type() == "none" {
            out_data = data;
        } else {
            println!("- Warning: unsupported compression type!");
            out_data = data;
        }

        let output_path = Path::new(&output_folder).join(pimg.name() + ".bin");

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
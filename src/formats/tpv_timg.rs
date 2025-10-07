use std::str;
use std::path::{Path};
use std::io::{Read, Write};
use std::fs::{self, File, OpenOptions};

use flate2::read::GzDecoder;

use crate::common;

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
        //PIMG
        let mut pimg = [0u8; 4];     
        if file.read_exact(&mut pimg).is_err() {
            break; //EOF
        } else {
            assert!(&pimg == b"PIMG", "Invalid PIMG section!");
        }

        let _ = common::read_exact(&mut file, 4)?; //4 bytes 00

        let size_bytes = common::read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        let _ = common::read_exact(&mut file, 4)?; //4 bytes 00

        let _checksum = common::read_exact(&mut file, 16)?; //16 bytes checksum? or maybe signature

        let name_bytes = common::read_exact(&mut file, 16)?;
        let name = common::string_from_bytes(&name_bytes);

        let dev_bytes = common::read_exact(&mut file, 64)?;
        let dev = common::string_from_bytes(&dev_bytes);

        let comp_bytes = common::read_exact(&mut file, 16)?;
        let comp_type = common::string_from_bytes(&comp_bytes);
    
        let _ = common::read_exact(&mut file, 1032)?; //1032 bytes maybe comment? skip this

        let data = common::read_exact(&mut file, size as usize)?;

        println!("\nPIMG: Name: {}, Size: {}, Dest: {}, Compression: {}", name, size, dev, comp_type);

        let out_data;

        if comp_type == "gzip" {
            println!("- Decompressing gzip...");
            out_data = decompress_gzip(&data)?;
        } else if comp_type == "none" {
            out_data = data;
        } else {
            println!("- Warning: unsupported compression type!");
            out_data = data;
        }

        let output_path = Path::new(&output_folder).join(name + ".bin");

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


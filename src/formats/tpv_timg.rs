use std::str;
use std::path::{Path};
use std::io::{self, Read, Write};
use std::fs::{self, File, OpenOptions};

use flate2::read::GzDecoder;

use crate::common;

pub fn is_tpv_timg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    let header_string = String::from_utf8_lossy(&header);

    if header_string == "TIMG"{
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

fn read_exact<R: Read>(reader: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn string_from_bytes(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

pub fn extract_tpv_timg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    //TIMG header
    let _timg = read_exact(&mut file, 288)?;

    loop {
        //PIMG
        let mut pimg = [0u8; 4];     
        if file.read_exact(&mut pimg).is_err() {
            break; //EOF
        } else {
            assert!(&pimg == b"PIMG", "Invalid PIMG section!");
        }

        //4 bytes 00
        let _ = read_exact(&mut file, 4)?;

        //4 bytes size
        let size_bytes = read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        //4 bytes nothing
        let _ = read_exact(&mut file, 4)?;

        //16 bytes checksum? or maybe signature
        let _checksum = read_exact(&mut file, 16)?;

        //16 bytes name
        let name_bytes = read_exact(&mut file, 16)?;
        let name = string_from_bytes(&name_bytes);

        //64 bytes destination device
        let dev_bytes = read_exact(&mut file, 64)?;
        let dev = string_from_bytes(&dev_bytes);

        //16 bytes compression type
        let comp_bytes = read_exact(&mut file, 16)?;
        let comp_type = string_from_bytes(&comp_bytes);

        //1032 bytes maybe comment? skip this
        let _ = read_exact(&mut file, 1032)?;

        //actual data
        let data = read_exact(&mut file, size as usize)?;

        println!("PIMG - Name: {} Size: {} Dest: {} Compression: {}", name, size, dev, comp_type);

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
            .append(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&out_data)?;

        println!("- Saved file!");
    }

    println!();
    println!("Extraction finished!");

    Ok(())
}


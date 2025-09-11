use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write};
use lz4::block::decompress;
use crate::common;

pub fn is_mstar_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 32768).expect("Failed to read from file.");
    let header_string = String::from_utf8_lossy(&header);

    if header_string.contains("filepartload") & header_string.contains("MstarUpgrade") | header_string.contains("CtvUpgrade") {
        true
    } else {
        false
    }
}

fn parse_number(s: &str) -> Option<u64> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16).ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

fn decompress_lz4(compressed_data: &[u8], original_size: i32) -> Result<Vec<u8>, std::io::Error> {
    match decompress(compressed_data, Some(original_size)) {
        Ok(decompressed) => Ok(decompressed),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

pub fn extract_mstar(file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    let mut script = common::read_file(&file, 0, 32768)?;

    if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
        script.truncate(pos);
    }

    let mut script_string = String::from_utf8_lossy(&script);
    //println!("{}", script_string);

    if script_string == "" {
        //try ts hisense
        println!("Failed to get script at 0x0, trying 0x1000...");
        script = common::read_file(&file, 4096, 32768)?;
        script_string = String::from_utf8_lossy(&script);

        if script_string == "" {
            println!("Failed to get script.");
        }
    }

    let lines: Vec<&str> = script_string.lines().map(|l| l.trim()).collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("filepartload") {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 5 {
                let offset = parse_number(parts[3]).unwrap_or(0);
                let size = parse_number(parts[4]).unwrap_or(0);

                //try to get partname from comment
                let mut partname = if let Some(idx) = line.find('#') {
                    line[idx + 1..].trim()
                } else {
                    "unknown"
                };

                let mut compression = "none";
                let mut lz4_expect_size = 0;
                let mut j = i + 1;
                while j < lines.len() && !lines[j].starts_with("filepartload") {
                    //get compression method
                    if lines[j].contains("mscompress7") {
                        compression = "lzma";
                    } else if lines[j].contains("lz4") {
                        compression = "lz4";
                    }

                    if lines[j].starts_with("lz4"){
                        let parts: Vec<&str> = lines[j].split_whitespace().collect();
                        lz4_expect_size = parse_number(parts[5]).unwrap_or(0);
                    }

                    // check if its boot partition
                    if lines[j].starts_with("mmc write.boot") {
                        if partname == "unknown" {
                            partname = "boot"
                        }
                    }

                    // try to get partname from nand/mmc/ubi writes
                    if lines[j].starts_with("mmc write") | lines[j].starts_with("nand write") | lines[j].starts_with("ubi write"){
                        let parts: Vec<&str> = lines[j].split_whitespace().collect();
                        if partname == "unknown" {
                            partname = parts[3]
                        }
                    }
   
                    j += 1;
                }

                println!("offset: {} size: {} --> {} (compression: {})", offset, size, partname, compression);

                let data = common::read_file(&file, offset, size.try_into().unwrap())?;

                //println!("{:02x?}", &data[0]);
                //println!("{}", data.len());

                let out_data;

                if compression == "lzma" {
                    // TODO: do lzma decompression
                    out_data = data;
                } else if compression == "lz4" {
                    println!("- Decompressing lz4, expected size: {}", lz4_expect_size);
                    out_data = decompress_lz4(&data, lz4_expect_size.try_into().unwrap())?;
                    //out_data = data;
                } else {
                    out_data = data;
                }

                let output_path = Path::new(&output_folder).join(partname.to_owned() + ".bin");

                fs::create_dir_all(&output_folder)?;
                let mut out_file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(output_path)?;

                out_file.write_all(&out_data)?;
            }
        }

        i += 1;
    }

    Ok(())
}
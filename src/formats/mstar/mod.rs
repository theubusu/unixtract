mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::io::Write;

use crate::utils::common;
use crate::utils::global::opt_dump_dec_hdr;
use crate::utils::compression::{decompress_lzma, decompress_lz4};
use crate::utils::lzop::{unlzop_to_file};
use crate::utils::sparse::{unsparse_to_file};
use include::*;

pub fn is_mstar_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 32768)?;
    let header_string = String::from_utf8_lossy(&header);
    if header_string.contains("filepartload"){
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_mstar(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let file = app_ctx.file().ok_or("Extractor expected file")?;

    let mut script = common::read_file(&file, 0, 32768)?;

    if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
        script.truncate(pos);
    }

    let mut script_string = String::from_utf8_lossy(&script);
    //println!("{}", script_string);
    if script_string == "" {
        //try for hisense
        println!("Failed to get script at 0x0, trying 0x1000...");
        script = common::read_file(&file, 4096, 32768)?;

        if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
            script.truncate(pos);
        }

        script_string = String::from_utf8_lossy(&script);

        if script_string == "" {
            return Err("Failed to get script".into());
        }
    }
    opt_dump_dec_hdr(app_ctx, &script, "script")?;

    let lines: Vec<&str> = script_string.lines().map(|l| l.trim()).collect();
    let mut i = 0;

    for line in &lines {
        if line.starts_with("filepartload") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let offset = parse_number(parts[3]).unwrap_or(0);
            let size = parse_number(parts[4]).unwrap_or(0);

            //try to get partname from comment
            //let mut partname = if let Some(idx) = line.find('#') {
            //    line[idx + 1..].trim()
            //} else {
            //    "unknown"
            //};
            let mut partname = "unknown";
            let mut compression = "none";
            let mut lz4_expect_size = 0;
            let mut j = i + 1;
                
            // get lines after this filepartload, before the next one
            while j < lines.len() && !lines[j].starts_with("filepartload") {
                //get compression method
                if lines[j].starts_with("mscompress7"){
                    if compression == "none" {
                        compression = "lzma";
                    } else if compression == "lzma" {
                        //thank the turks
                        compression = "double_lzma";
                    }
                }
                if lines[j].starts_with("lz4"){
                    compression = "lz4";
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    lz4_expect_size = parse_number(parts[5]).unwrap_or(0);
                }
                if lines[j].starts_with("mmc unlzo"){
                    compression = "lzo";
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    // get part name from mmc unlzo
                    if partname == "unknown" {
                        partname = parts[4]
                    }
                }
                if lines[j].starts_with("sparse_write"){
                    compression = "sparse"; //its not really compression but anyway
                    let parts: Vec<&str> = lines[j].split_whitespace().collect();
                    // get part name from sparse_write
                    if partname == "unknown" {
                        partname = parts[3]
                    }
                }

                // check if its boot partition
                if lines[j].starts_with("mmc write.boot") {
                    if partname == "unknown" {
                        partname = "_mmc_boot"
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

            println!("\nPart - Offset: {}, Size: {} --> {}", offset, size, partname);

            if partname == "unknown" {
                println!("- Unknown destination, skipping!");
            } else {
                let data = common::read_file(&file, offset, size.try_into().unwrap())?;
                let out_data; 
                let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", partname));

                if compression == "lzma" {
                    println!("- Decompressing LZMA...");
                    out_data = decompress_lzma(&data)?;
                } else if compression == "double_lzma" {
                    println!("- Decompressing LZMA (Pass 1)...");
                    let pass_1 = decompress_lzma(&data)?;
                    println!("- Decompressing LZMA (Pass 2)...");
                    out_data = decompress_lzma(&pass_1)?;
                } else if compression == "lz4" {
                    println!("- Decompressing lz4, expected size: {}", lz4_expect_size);
                    out_data = decompress_lz4(&data, lz4_expect_size.try_into().unwrap())?;
                } else if compression == "lzo" {
                    println!("- Decompessing LZO..");
                    unlzop_to_file(&data, output_path)?;
                    println!("-- Saved file!");
                    i += 1;
                    continue
                } else if compression == "sparse" {
                    println!("- Unsparsing...");
                    unsparse_to_file(&data, output_path)?;
                    println!("-- Saved file!");
                    i += 1;
                    continue
                } else {
                    out_data = data;
                }

                fs::create_dir_all(&app_ctx.output_dir)?;
                let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
                out_file.write_all(&out_data)?;
                println!("-- Saved file!");
            }
        }

        i += 1;
    }

    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::io::{Seek, Write};
use std::fs::{self, OpenOptions};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::compression::{decompress_gzip};
use crate::utils::sparse::{unsparse_to_file};
use include::*;

pub fn is_nvt_timg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"TIMG" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_nvt_timg(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let file_size = file.metadata()?.len();
    let timg: TIMG = file.read_le()?;
    println!("File info:\nData size: {}", timg.data_size);

    let mut pimg_i = 0;
    while file.stream_position()? < file_size as u64 {
        pimg_i += 1;
        let pimg: PIMG = file.read_le()?;
        if &pimg.magic_bytes != b"PIMG" {
            return Err("Invalid PIMG magic!".into());
        }

        let data = common::read_exact(&mut file, pimg.size as usize)?;

        println!("\n#{} - {}, Size: {}, Dest: {}, Compression: {}", pimg_i, pimg.name(), pimg.size, pimg.dest_dev(), pimg.comp_type());

        let out_data;
        let output_path = Path::new(&app_ctx.output_dir).join(pimg.name() + ".bin");

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
            println!("- Warning: unsupported compression type, saving stored data!");
            out_data = data;
        }

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");
    }

    Ok(())
}
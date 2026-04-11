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

pub struct TimgContext {
    variant: TimgVariant,
}

pub fn is_nvt_timg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 8)?;
    if header == b"TIMG\x00\x00\x00\x00" {  //new variant checks magic as 64bit int (probably)
        Ok(Some(Box::new(TimgContext {variant: TimgVariant::New})))

    } else if header.starts_with(b"TIMG") {
        //check based on where the first PIMG appears, since Old2 header is 4 bytes bigger, it will appear later
        let check = common::read_file(&file, 280, 8)?;
        if &check[0..4] == b"PIMG" {
            Ok(Some(Box::new(TimgContext {variant: TimgVariant::Old})))
        }
        else if &check[4..8] == b"PIMG" {
            Ok(Some(Box::new(TimgContext {variant: TimgVariant::Old2})))
        }
        else {
            Ok(None)    //?
        }        
    } else {
        Ok(None)
    }
}

pub fn extract_nvt_timg(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<TimgContext>().expect("Missing context");

    let timg: Box<dyn TIMG> = match ctx.variant {
        TimgVariant::New => Box::new(file.read_le::<TIMG64>()?),
        TimgVariant::Old => Box::new(file.read_le::<TIMG32>()?),
        TimgVariant::Old2 => Box::new(file.read_le::<TIMGOld2>()?),
    };
    println!("File info:\nVariant: {:?}\nData size: {}", ctx.variant, timg.data_size());

    //position after header + data size
    let end = file.stream_position()? + timg.data_size() as u64;

    let mut pimg_i = 0;
    while file.stream_position()? < end {
        pimg_i += 1;

        let pimg: Box<dyn PIMG> = match ctx.variant {
            TimgVariant::New => Box::new(file.read_le::<PIMG64>()?),
            TimgVariant::Old => Box::new(file.read_le::<PIMG32>()?),
            TimgVariant::Old2 => Box::new(file.read_le::<PIMGOld2>()?),
        };

        if !pimg.magic_bytes().starts_with(b"PIMG") {
            return Err("Invalid PIMG magic!".into());
        }

        let data = common::read_exact(&mut file, pimg.size())?;

        println!("\n#{} - {}, Size: {}, Dest: {}, Compression: {}, Comment: {}",
                pimg_i, pimg.name(), pimg.size(), pimg.dest_dev(), pimg.comp_type(), pimg.comment());

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
mod include;
use std::any::Any;
use crate::{AppContext, InputTarget, formats};

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Seek};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

struct PhilipsBdpCtx {
    header_type: HeaderType,
}

pub fn is_philips_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 16)?;
    if header.starts_with(b"PHILIPS") {
        if header[15].is_ascii_alphanumeric() {
            Ok(Some(Box::new(PhilipsBdpCtx {header_type: HeaderType::New})))
        } else {
            Ok(Some(Box::new(PhilipsBdpCtx {header_type: HeaderType::Old})))
        }
    } else {
        Ok(None)
    }
}

pub fn extract_philips_bdp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<PhilipsBdpCtx>().expect("Missing context");

    let header: Box<dyn UpgHeader> = match ctx.header_type {
        HeaderType::Old => Box::new(file.read_le::<UpgHeaderOld>()?),
        HeaderType::New => Box::new(file.read_le::<UpgHeaderNew>()?),
    };

    let header_size = file.stream_position()?;

    println!("File info -\nName: {}\nVersion: {}\nTarget size: {}\nEntry count: {}\nHeader type: {:?}\nHeader size: {}",
            header.name(), header.version(), header.target_size(), header.target_num(), ctx.header_type, header_size);
    
    for (i, entry) in header.entries().iter().enumerate() {
        if entry.id == 0xFF && entry.size == 0xFFFFFFFF {
            break
        }

        println!("\n#{} - ID: {:x}, IIC: {:x}, Version: {}, Offset: {}, Size: {}", 
                i+1, entry.id, entry.iic, entry.version(), entry.offset, entry.size);

        let data = common::read_file(&file, entry.offset as u64 + header_size, entry.size as usize)?;

        let out_data;
        if entry.id == 0 && app_ctx.has_option("philips_bdp:decrypt") {
            println!("- Decrypting...");
            out_data = bebin_decrypt_aes256cfb(&data, &KEY1, &IV1);
        } else {
            out_data = data;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.id));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;       
        out_file.write_all(&out_data)?;

        println!("- Saved file!");

        //ID 0 should be the main MTK bdp file, since this is just an extra container for that format (like Sony BDP), so we can try to extract it here.
        if entry.id == 0 {
            println!("Checking if it's also MTK BDP...");

            let new_file = File::open(&output_path)?;
            //DUMB
            let mtk_ctx: AppContext = AppContext { input: InputTarget::File(new_file), output_dir: app_ctx.output_dir.join("0"), options: app_ctx.options.clone() };

            if let Some(result) = formats::mtk_bdp::is_mtk_bdp_file(&mtk_ctx)? {
                println!("- MTK BDP file detected!\n");
                formats::mtk_bdp::extract_mtk_bdp(&mtk_ctx, result)?;
            } else {
                if app_ctx.has_option("philips_bdp:decrypt") {
                    println!("- Not an MTK BDP file"); 
                } else {
                    println!("- Not an MTK BDP file (try with decrypt?)"); 
                }                   
            }
        }
    }

    Ok(())
}
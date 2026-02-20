mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;
use binrw::BinReaderExt;

use crate::utils::common;
use crate::keys;
use crate::formats::funai_upg::funai_des::funai_des_decrypt;
use crate::formats::funai_upg::include::is_valid_ver_string;
use include::*;

pub fn is_funai_upg_phl_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 8)?;

    //assume 2 extra zeros since first "body" (not my name for it btw) is always Type 0
    if header == b"UPG\x00\x00\x00\x00\x00"{
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_funai_upg_phl(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    let mut key: Option<u32> = None;

    for (i, entry) in header.entries.iter().enumerate() {
        if entry.body_type == 0xFFFF && entry.size == 0 {
            continue
        }

        let mut data = common::read_exact(&mut file, entry.size as usize)?;

        //find key using descriptor entry
        if entry.body_type == 0 && key.is_none() {
            for key_hex in keys::FUNAI_UPG {
                let key_bytes = hex::decode(key_hex)?;
                let key_u32 = u32::from_le_bytes(key_bytes.as_slice().try_into()?);
                let decrypted = funai_des_decrypt(&data, key_u32);

                if is_valid_ver_string(&decrypted[..16]) {
                    println!("Matched key: {}\nFirmware info: {}\nFirmware date: {}", 
                            key_hex, common::string_from_bytes(&decrypted[..16]), common::string_from_bytes(&decrypted[16..]));
                    key = Some(key_u32);
                    break
                }
            }
        }

        println!("\n#{} - Type: {}, Size: {}", i + 1, entry.body_type, entry.size);

        if let Some(key_u32) = key {
            println!("- Decrypting...");
            data = funai_des_decrypt(&data, key_u32);

        } else {
            println!("- Warning! Failed to find decryption key, saving encrypted data")
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.body_type));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");

    }

    Ok(())
}
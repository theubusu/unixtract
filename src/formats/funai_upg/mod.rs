pub mod include;
pub mod funai_des;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;
use crate::keys;
use funai_des::funai_des_decrypt;

pub fn is_funai_upg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 8)?;
    let entry_count = u16::from_le_bytes(header[6..8].try_into()?);
    if header[..6] == *b"UPG\x00\x00\x00" && entry_count > 0 {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_funai_upg(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    let mut key: Option<u32> = None;

    println!("File info:\nFile size: {}\nEntry count: {}", header.file_size, header.entry_count);
    
    for i in 0..header.entry_count {
        let entry: Entry = file.read_le()?;
        
        let mut data = common::read_exact(&mut file, entry.entry_size as usize - 0x46)?; //size has the flags + crc32 + hash
        let _crc32 = common::read_exact(&mut file, 4)?; //crc32 includes the entry header and hash
        let _hash = common::read_exact(&mut file, 64)?; //hash is only used on encrypted entries

        //find key using descriptor entry
        if entry.entry_type == 0 && entry.encryption_flag == 1 && key.is_none() {
            for key_hex in keys::FUNAI_UPG {
                let key_bytes = hex::decode(key_hex)?;
                let key_u32 = u32::from_le_bytes(key_bytes.as_slice().try_into()?);
                let decrypted = funai_des_decrypt(&data, key_u32);

                if is_valid_ver_string(&decrypted) {
                    println!("Matched key: {}\nFirmware info: {}", 
                            key_hex, common::string_from_bytes(&decrypted));
                    key = Some(key_u32);
                    break
                }
            }
        }

        println!("\n({}/{}) - Type: {}, Size: {}", i + 1, header.entry_count, entry.entry_type, entry.entry_size);

        if entry.encryption_flag == 1 {
            if let Some(key_u32) = key {
                println!("- Decrypting...");
                data = funai_des_decrypt(&data, key_u32);
            } else {
                println!("- Warning! Failed to find decryption key, saving encrypted data")
            }
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.entry_type));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");
    }
    
    Ok(())
}
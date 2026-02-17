mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use binrw::BinReaderExt;
use std::io::{Write, Seek, SeekFrom, Cursor};

use crate::utils::common;
use crate::keys;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};
use include::*;

pub fn is_ruf_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 6)?;
    if header == b"RUF\x00\x00\x00" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_ruf(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: RufHeader = file.read_be()?;
    if header.is_dual_ruf() {
        println!("\nDual RUF detected! Extracting 1st RUF...\n");
        actually_extract_ruf(file, &app_ctx.output_dir.join("RUF_1"), 0)?;
        println!("\nExtracting 2nd RUF...\n");
        actually_extract_ruf(file, &app_ctx.output_dir.join("RUF_2"), 41943088)?;
    } else {
        actually_extract_ruf(file, &app_ctx.output_dir, 0)?;
    }

    Ok(())
}

fn actually_extract_ruf(mut file: &File, output_folder: &PathBuf, start_offset: u64) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(start_offset))?;
    let header: RufHeader = file.read_be()?;

    println!("File info:\nBuyer: {} \nModel: {} \nRegion Info: {} \nDateTime: {}\nVersion:{:02x?} \nData Size: {} \nDual RUF: {}",
            header.buyer(), header.model(), header.region_info(), header.date_time(), header.version_bytes, header.data_size, header.is_dual_ruf());
    
    println!("\nPayload count: {}", header.payload_count);
    file.seek(SeekFrom::Start(start_offset + header.payloads_start_offset as u64))?;

    let mut entries: Vec<RufEntry> = Vec::new();

    let mut vi = 0;
    for _i in 0..28 {
        if vi == header.payload_count {
            break
        }
        let entry: RufEntry = file.read_be()?;

        if entry.payload_type_bytes == 0 && entry.size == 0 {
            continue
        } else {
            vi += 1
        }

        println!("{}/{}: Type: {}({}), Size: {}",
                vi, header.payload_count, entry.payload_type_bytes, entry.payload_type(), entry.size);
        
        entries.push(entry);
    }

    let mut key: Option<&str> = None;
    let key_bytes;
    let iv_bytes: [u8; 16] = [0x00; 16];

    //find key
    for (prefix, value) in keys::RUF {
        if header.model().starts_with(prefix) {
            key = Some(value);
            break;
        }
    }
    if let Some(k) = key {
        println!("\nKey: {}", k);
        key_bytes = hex::decode(k)?.as_slice().try_into()?;
    } else {
        return Err("This firmware is not supported!".into());
    }

    file.seek(SeekFrom::Start(start_offset + 2048))?;
    let encrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    println!("Decrypting data...");
    let decrypted_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &key_bytes, &iv_bytes)?;

    let mut data_reader = Cursor::new(decrypted_data);

    let mut ei = 1;
    for entry in entries {
        println!("\n({}/{}) - {}({}), Size: {}",
            ei, header.payload_count, entry.payload_type_bytes, entry.payload_type(), entry.size);

        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&output_folder).join(format!("{}_{}.bin", entry.payload_type_bytes, entry.payload_type()));
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");

        ei += 1;
    }

    Ok(())
}
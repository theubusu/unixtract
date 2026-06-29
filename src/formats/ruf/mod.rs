mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use binrw::BinReaderExt;
use std::io::{Write, Seek, SeekFrom, Cursor};

use crate::utils::common;
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

    println!("File info:\nBuyer: {} \nModel: {} \nRegion Info: {} \nDateTime: {}\nVersion:{:02x?} \nData Size: {} \nDual RUF: {}",
            header.buyer(), header.model(), header.region_info(), header.date_time(), header.version_bytes, header.data_size, header.is_dual_ruf());
    
    println!("\nPayload count: {}", header.payload_count);
    file.seek(SeekFrom::Start(header.payloads_start_offset as u64))?;

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

    let mut key: Option<&Vec<u8>> = None;
    let key_bytes;
    let iv_bytes: [u8; 16] = [0x00; 16];

    //find key
    for (name, keys) in app_ctx.keys.get_collection("RUF")? {
        if header.model().starts_with(name) {
            key = Some(keys.first().unwrap());
            break;
        }
    }
    if let Some(k) = key {
        key_bytes = k.as_slice().try_into()?;
    } else {
        return Err("no key found for this firmware".into());
    }

    file.seek(SeekFrom::Start(header.data_start_offset.into()))?;
    let encrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    println!("Decrypting data...");
    let decrypted_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &key_bytes, &iv_bytes)?;

    let mut data_reader = Cursor::new(decrypted_data);

    let mut ei = 1;
    for entry in entries {
        println!("\n({}/{}) - {}({}), Size: {}",
            ei, header.payload_count, entry.payload_type_bytes, entry.payload_type(), entry.size);

        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", entry.payload_type_bytes, entry.payload_type()));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");

        ei += 1;
    }

    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Seek, SeekFrom, Cursor};
use binrw::BinReaderExt;

use crate::utils::aes::{decrypt_aes128_cbc_pcks7};
use crate::utils::common;
use include::*;

pub fn is_invincible_image_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 16)?;
    if header == b"INVINCIBLE_IMAGE" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_invincible_image(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    println!("File info -\nFile Version: {}\nVersion(1): {}\nVersion(2): {}\nVersion(3): {}\nVersion(4): {}\nData size: {}\nChunk count: {}\nChunk size: {}\n\nPayload Count: {}",
            header.file_infos[0], header.ver1(), header.ver2(), header.ver3(), header.ver4(), header.data_size, header.chunk_count, header.chunk_size, header.payload_count);

    let mut entries: Vec<Entry> = Vec::new();

    for i in 0..header.payload_count {
        let entry: Entry = file.read_le()?;
        println!("{}. {} - Start offset: {}, Size: {}", 
                i + 1, entry.name(), entry.start_offset, entry.size);
        entries.push(entry);
    }

    let (aes_key, aes_iv) = match header.file_infos[0] {
        3 => (V3_KEY, V3_IV),
        _ => return Err("Unsupported format version! (Unknown key)".into())
    };

    file.seek(SeekFrom::Start(header.data_start_offset.into()))?;

    let mut encrypted_data = Vec::with_capacity(header.data_size as usize);

    if header.chunk_count == 0 {    //not chunked, read all data
        encrypted_data = common::read_exact(&mut file, header.data_size as usize)?;

    } else {
        let mut buffer = vec![0u8; header.chunk_size as usize];
        let mut remain = header.data_size as usize;

        for _ in 0..header.chunk_count {
            let read_size = remain.min(buffer.len());
            let bytes_read = file.read(&mut buffer[..read_size])?;
            encrypted_data.extend_from_slice(&buffer[..bytes_read]);
            remain -= bytes_read;

            file.seek(SeekFrom::Current(header.signature_size.into()))?; // skip signature in each chunk
        }
    }

    println!("\nDecrypting data...");
    let decrypted_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &aes_key, &aes_iv)?;

    let mut data_reader = Cursor::new(decrypted_data);

    for (i , entry) in entries.iter().enumerate() {
        println!("\n({}/{}) - {}, Size: {}, Start offset: {}", i+1, header.payload_count, entry.name(), entry.size, entry.start_offset);

        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(entry.name() + ".bin");
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

        out_file.seek(SeekFrom::Start(entry.start_offset.into()))?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
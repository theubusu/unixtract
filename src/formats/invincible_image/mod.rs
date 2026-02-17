mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Seek, SeekFrom, Cursor};
use binrw::BinReaderExt;

use crate::utils::aes::{decrypt_aes128_cbc_nopad};
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
    println!("File info:\nFile Version: {}.{}\nVersion(1): {}\nVersion(2): {}\nVersion(3): {}\nVersion(4): {}\nData size: {}\nData start offset: {}\nKeep data size: {}\nSkip data size: {}\n\nPayload Count: {}",
            header.file_version[0], header.file_version[1], header.ver1(), header.ver2(), header.ver3(), header.ver4(), header.data_size, header.data_start_offset, header.keep_size, header.skip_size, header.payload_count);

    let mut entries: Vec<Entry> = Vec::new();

    for i in 0..header.payload_count {
        let entry: Entry = file.read_le()?;
        println!("{}. {}, Start offset: {}, Size: {}", 
                i + 1, entry.name(), entry.start_offset, entry.size);
        entries.push(entry);
    }

    if header.file_version[0] != 3 {
        println!("\nSorry, this version of the file is not supported!");
        return Ok(())
    }

    let mut encrypted_data = Vec::new();
    let mut buffer = vec![0u8; header.keep_size as usize];

    file.seek(SeekFrom::Start(header.data_start_offset.into()))?;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // EOF
        }
        encrypted_data.extend_from_slice(&buffer[..bytes_read]);
        file.seek(SeekFrom::Current(header.skip_size.into()))?;
    }

    println!("\nDecrypting data...");
    let decrypted_data = decrypt_aes128_cbc_nopad(&encrypted_data, &V3_KEY, &V3_IV)?;

    let mut data_reader = Cursor::new(decrypted_data);

    let mut i = 1;
    for entry in entries {
        println!("\n({}/{}) - {}, Size: {}", i, header.payload_count, entry.name(), entry.size);
        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(entry.name() + ".bin");

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
        i += 1;
    }

    println!("\nExtraction finished!");

    Ok(())
}
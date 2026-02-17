mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::io::{Write, Seek, Read, Cursor};
use tar::Archive;
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes128_cbc_pcks7};
use include::*;

pub fn is_roku_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 32)?;
    let try_decrypt_header = decrypt_aes128_cbc_nopad(&header, &FILE_KEY, &FILE_IV)?;

    if try_decrypt_header.starts_with(b"manifest\x00\x00\x00\x00\x00\x00\x00\x00") {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_roku(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    println!("\nDecrypting...\n");
    let tar_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &FILE_KEY, &FILE_IV)?;
    let tar_reader = Cursor::new(tar_data);
    let mut tar_archive = Archive::new(tar_reader);

    for entry_result in tar_archive.entries_with_seek()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();

        if path == std::path::Path::new("manifest") {
            let size = entry.header().size()? as usize;
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;

            let text = String::from_utf8_lossy(&contents[..size - 256]); //dont display signature
            println!("Manifest file:\n{}", text);
        } else {
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?; //entry cant seek
            
            if contents.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\x00imgARMcC") {
                println!("\nImage file: {:?}:", path);
                let size = entry.header().size()? as usize;
                let mut image_reader = Cursor::new(contents);
                let mut i = 1;

                while image_reader.stream_position()? < size as u64 {
                    let image: ImageHeader = image_reader.read_le()?;
                    println!("\nImage {} - Type: {:x}({}), Size: {}, Flags: {:x}{}, Data offset: {}", 
                            i ,image.image_type, image.type_string(), image.size1, image.flags, if image.is_encrypted(){"(Encrypted)"}else{" "}, image.data_start_offset);
                    
                    let data = 
                    if image.data_start_offset == 0 {
                        common::read_exact(&mut image_reader, image.size1 as usize - 256)?
                    } else {
                        let _extra_data = common::read_exact(&mut image_reader, image.data_start_offset as usize - 256)?;
                        common::read_exact(&mut image_reader, image.size1 as usize - image.data_start_offset as usize)?
                    };

                    let folder_path = Path::new(&app_ctx.output_dir).join(&path);
                    let output_path = Path::new(&folder_path).join(format!("{}_{}.bin", i, image.type_string()));

                    fs::create_dir_all(&folder_path)?;
                    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                    out_file.write_all(&data)?;

                    println!("- Saved file!");

                    i += 1;
                }

            } else {
                println!("\nOther/Unknown file: {:?}", path);
                let output_path = Path::new(&app_ctx.output_dir).join(&path);

                fs::create_dir_all(&app_ctx.output_dir)?;
                let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                out_file.write_all(&contents)?;

                println!("- Saved file!");
            }
        }
    }

    println!("\nExtraction finished!");
    Ok(())
}
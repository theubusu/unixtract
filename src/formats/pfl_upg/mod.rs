mod include;
use std::any::Any;
use crate::{AppContext, InputTarget};

use std::path::Path;
use std::io::{Cursor, Write};
use std::fs::{self, File, OpenOptions};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_pfl_upg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 8)?;
    if header == b"2SWU3TXV" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_pfl_upg(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?; 
    let signature = common::read_exact(&mut file, 128)?;
    let _ = common::read_exact(&mut file, 32)?; //unknown

    let version_bytes = common::read_exact(&mut file, header.header_size as usize - 704)?;  //704 is base header size
    let version = common::string_from_bytes(&version_bytes);

    println!("\nVersion: {}", version);
    if header.description() != "" { //look ugly when empty
        println!("--- Description --- \n{}", header.description());
        println!("-------------------");
    }
    println!("Data size: {}", header.data_size);

    let mut data;
    if header.is_encrypted() {
        println!("\nFile is encrypted.");
        
        //get some data as test ciphertext for key finding
        let ciphertext = common::read_file(&mut file, header.header_size as u64, 64)?;
        let aes_key;
        if let Some((key_name, key)) = try_find_key(&signature, &ciphertext)? {
            println!("Matched pubkey: {}, AES key: {}", key_name, hex::encode(key));
            aes_key = key;
        } else {
            return Err("Matching key not found, cannot decrypt data".into());
        }

        //need to align to 16 bytes for AES blocksize
        let encrypted_data = common::read_exact(&mut file, (header.data_size as usize + 0xf) & !0xf)?;

        println!("Decrypting data...");
        data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
        data.truncate(header.data_size as usize);   //discard padding 
        
    } else {
        data = common::read_exact(&mut file, header.data_size as usize)?;
    }

    let mut data_reader = Cursor::new(data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        let file_header: FileHeader = data_reader.read_le()?; 

        if file_header.is_folder() {
            println!("\nFolder - {}", file_header.file_name());
            let output_path = Path::new(&app_ctx.output_dir).join(file_header.file_name().trim_start_matches('/'));
            fs::create_dir_all(output_path)?;
            continue
        }

        let file_name = if file_header.has_extended_name() {
            let ex_name_size = file_header.header_size - 76; //76 is base file header size
            let ex_name_bytes = common::read_exact(&mut data_reader, ex_name_size as usize)?;
            common::string_from_bytes(&ex_name_bytes)
        } else {
            file_header.file_name()
        };

        println!("\nFile - {}, Size: {}", file_name, file_header.real_size);
        let data = common::read_exact(&mut data_reader, file_header.stored_size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(file_name.trim_start_matches('/'));

        fs::create_dir_all(&app_ctx.output_dir)?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        //pfl upg inside pfl upg! DUMB code!
        if file_header.is_package() && !app_ctx.has_option("pfl_upg:no_extract_inner_upg"){
            println!("- Extracting inner UPG...");

            //save this as temp file
            let temp_path = Path::new(&app_ctx.output_dir).join("inner_upg_temp");
            let mut temp_file = OpenOptions::new().write(true).create(true).open(&temp_path)?;
            temp_file.write_all(&data[..file_header.real_size as usize])?;

            //REOPEN temp file and make ctx
            let r_temp_file = File::open(&temp_path)?;
            let in_ctx: AppContext = AppContext { 
                input: InputTarget::File(r_temp_file), 
                output_dir: output_path, 
                options: app_ctx.options.clone() 
            };

            //do check just in case and extract
            if let Some(result) = is_pfl_upg_file(&in_ctx)? {
                extract_pfl_upg(&in_ctx, result)?;
            } else {
                return Err("detection on inner UPG failed!".into());                 
            }

            //delete temp file
            fs::remove_file(&temp_path)?;

            continue
        }
        
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data[..file_header.real_size as usize])?;
        println!("- Saved file!");
    }
    
    Ok(())
}
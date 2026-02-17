mod include;
use std::any::Any;
use crate::AppContext;

use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::path::Path;
use std::io::{Read, Cursor, Write};
use std::fs::{self, OpenOptions};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::keys;
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

    let version_bytes = common::read_exact(&mut file, header.header_size as usize - 704)?;
    let version = common::string_from_bytes(&version_bytes);

    println!("\nVersion: {}", version);
    println!("Description: \n{}", header.description());
    println!("Data size: {}", header.data_size);

    let mut decrypted_data;
    if (header.mask & 0x2000_0000) != 0 {
        println!("File is encrypted.");
        let mut key = None;
        let mut n_hex = None;

        //find key
        for (firmware, value) in AUTO_FWS {
            if version.starts_with(firmware) {
                key = Some(value);
                break;
            }
        }
        if key.is_none() {
            return Err("This firmware is not supported!".into());
        }

        //get key
        for (prefix, value) in keys::PFLUPG {
            if key == Some(prefix) {
                n_hex = Some(value);
                break;
            }
        }

        let e_hex = "010001";

        let n = BigUint::from_bytes_be(&decode(n_hex.unwrap())?);
        let e = BigUint::from_bytes_be(&decode(e_hex)?);
        let pubkey = RsaPublicKey::new(n, e)?;

        let signature_int = BigUint::from_bytes_le(&signature);

        let decrypted_int = rsa::hazmat::rsa_encrypt(&pubkey, &signature_int)?;
        let decrypted = decrypted_int.to_bytes_le();

        let aes_key = &decrypted[20..52];
        println!("AES key: {}\n", hex::encode(aes_key));

        //for encrypted data we need to read file to end
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        println!("Decrypting data...");
        decrypted_data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
        decrypted_data.truncate(header.data_size as usize);
        
    } else {
        println!("File is not encrypted.");
        decrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    }

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        let file_header: FileHeader = data_reader.read_le()?; 

        //its a folder not a file
        if (file_header.attributes[3] & (1 << 1)) != 0 {
            println!("\nFolder - {}", file_header.file_name());
            let output_path = Path::new(&app_ctx.output_dir).join(file_header.file_name().trim_start_matches('/'));
            fs::create_dir_all(output_path)?;
            continue
        }

        //extended name is used
        let file_name = if (file_header.attributes[2] & (1 << 7)) != 0 {
            let ex_name_size = file_header.header_size - 76; //76 is base file header size
            //println!("extended name {}, org name: {}", ex_name_size, file_header.file_name());
            let ex_name_bytes = common::read_exact(&mut data_reader, ex_name_size as usize)?;
            common::string_from_bytes(&ex_name_bytes)
        } else {
            file_header.file_name()
        };

        println!("\nFile - {}, Size: {}", file_name, file_header.real_size);
        let data = common::read_exact(&mut data_reader, file_header.stored_size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(file_name.trim_start_matches('/'));
        let output_path_parent = output_path.parent().expect("Failed to get parent of the output path!");

        //prevent collisions
        if output_path_parent.exists() && output_path_parent.is_file() {
            println!("[!] Warning: File collision detected, Skipping this file!");
            continue
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

        out_file.write_all(&data[..file_header.real_size as usize])?;

        //if it contains a PFL upg in itself to extract
        //if (file_header.attributes[3] & (1 << 2)) != 0 {
        //   println!("Container file");
        //}

        println!("- Saved file!");
    }
    
    Ok(())
}
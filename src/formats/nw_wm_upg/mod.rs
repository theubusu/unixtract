mod include;
use std::any::Any;
use crate::AppContext;
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes128_ecb};

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;

use crate::utils::common;
use include::*;

struct NwWmUpgCtx {
    key_name: String,
    encryption: EncryptionMode,
}

pub fn is_nw_wm_upg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let enc_hdr = common::read_file(&file, 16, 32)?;

    let (aes_passkey, aes_passiv) = app_ctx.keys.get_double_key_as_arr::<16, 16>("NW_WM_UPG_AES_PASS")?;
    let des_passkey = app_ctx.keys.get_key_as_arr::<8>("NW_WM_UPG_DES_PASSKEY", 0)?;
    for (name, keys) in app_ctx.keys.get_collection("NW_WM_UPG_KAS")? {
        let kas_bytes= keys.first().unwrap();
        if kas_bytes.len() == 32 {  //AES
            let decrypted_kas = decrypt_aes128_cbc_nopad(&kas_bytes, &aes_passkey, &aes_passiv)?;
            let aes_key: [u8; 16] = decrypted_kas[..16].try_into().unwrap();
            let signature = &decrypted_kas[16..];

            let decrypted_hdr = decrypt_aes128_ecb(&aes_key, &enc_hdr)?;
            if &decrypted_hdr[..16] == signature {
                return Ok(Some(Box::new(NwWmUpgCtx {key_name: name.to_string(), encryption: EncryptionMode::Aes(aes_key)})));
            }

        } else if kas_bytes.len() == 16 { //DES
            let decrypted_kas = decrypt_des_ecb(&des_passkey, &kas_bytes)?;
            let des_key: [u8; 8] = decrypted_kas[..8].try_into().unwrap();
            let signature = &decrypted_kas[8..];

            let decrypted_hdr = decrypt_des_ecb(&des_key, &enc_hdr)?;
            if &decrypted_hdr[..8] == signature {
                return Ok(Some(Box::new(NwWmUpgCtx {key_name: name.to_string(), encryption: EncryptionMode::Des(des_key)})));
            }
        }
    }

    Ok(None)
    
}

pub fn extract_nw_wm_upg(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<NwWmUpgCtx>().expect("Missing context");

    println!("Using key: {}", ctx.key_name);

    let _md5 = common::read_exact(&mut file, 16)?;

    let entry_count = match ctx.encryption {
        EncryptionMode::Aes(key) => {
            let enc_hdr = common::read_exact(&mut file, 32)?;
            let dec_hdr = decrypt_aes128_ecb(&key, &enc_hdr)?;
            u32::from_le_bytes(dec_hdr[16..20].try_into().unwrap())
        },
        EncryptionMode::Des(key) => {
            let enc_hdr = common::read_exact(&mut file, 16)?;
            let dec_hdr = decrypt_des_ecb(&key, &enc_hdr)?;
            u32::from_le_bytes(dec_hdr[8..12].try_into().unwrap())
        }
    };

    println!("\nEntry count: {}", entry_count);
    let mut entries: Vec<(u32, u32)> = Vec::new();

    for i in 0..entry_count {
        let entry = match ctx.encryption {
            EncryptionMode::Aes(key) => {
                let enc_entry = common::read_exact(&mut file, 16)?;
                decrypt_aes128_ecb(&key, &enc_entry)?
            },
            EncryptionMode::Des(key) => {
                let enc_entry = common::read_exact(&mut file, 8)?;
                decrypt_des_ecb(&key, &enc_entry)?
            }
        };
        let offset = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let size: u32 = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        println!("- Entry {} - offset: {}, size: {}", i+1, offset, size);
        entries.push((offset, size));
    }

    for (i, (offset, size)) in entries.iter().enumerate() {
        println!("\n({}/{}) - Offset: {}, Size: {}", i+1, entry_count, offset, size);

        //align to encryption block size
        let align_size = match ctx.encryption {
            EncryptionMode::Aes(_) => (size + 15) & !15,
            EncryptionMode::Des(_) => (size + 7) & !7,
        };

        let enc_data = common::read_file(&mut file, *offset as u64, align_size as usize)?;
        println!("- Decrypting...");
        let mut dec_data = match ctx.encryption {
            EncryptionMode::Aes(key) => {
                let aes_passiv = app_ctx.keys.get_key_as_arr::<16>("NW_WM_UPG_AES_PASS", 1)?;
                decrypt_aes128_cbc_nopad(&enc_data, &key, &aes_passiv)?
            },
            EncryptionMode::Des(key) => {
                decrypt_des_ecb(&key, &enc_data)?
            }
        };
        dec_data.truncate(*size as usize);

        if is_compressed_zlib(&dec_data) {
            println!("-- Zlib compression detected, decompressing...");
            dec_data = decompress_zlib_file(&dec_data)?;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i+1));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;
        out_file.write_all(&dec_data)?;
        println!("-- Saved file!");
    }
    
    Ok(())
}
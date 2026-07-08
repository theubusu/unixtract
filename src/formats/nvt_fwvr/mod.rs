mod include;
use std::any::Any;
use crate::{AppContext, InputTarget};
use crate::utils::aes::decrypt_aes256_cbc_pcks7;

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use binrw::BinReaderExt;
use sha2::{Digest, Sha256};

use crate::formats::nvt_timg_pkg::{extract_nvt_timg_pkg, is_nvt_timg_pkg_file};
use crate::utils::common;
use include::*;

pub fn is_nvt_fwvr_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let file_size = file.metadata()?.len();
    if  file_size > 512+16+32 { // version_info part inside TIMG's also starts with FWVR, but does not contain any firmware. ignore those
        let magic = common::read_file(&file, 0, 4)?;
        if magic == b"FWVR" {
            Ok(Some(Box::new(())))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

pub fn extract_nvt_fwvr(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    
    let header: FwvrHeader = file.read_le()?;
    println!("File info -\nMajor ver: {}\nMinor ver: {}\nDescription:\n{}\n", header.major_ver, header.minor_ver, header.description());

    let iv = common::read_exact(&mut file, 16)?;
    println!("IV:  {}", hex::encode(&iv));
    //derive key using SHA256 from IV
    let mut state: [u8; 32] = [0u8; 32];
    state[..16].copy_from_slice(&iv);

    let salt = app_ctx.keys.get_key_as_arr::<512>("NVT_FWVR_FW_DEC_KEY_BIN", 0)?;

    for _ in 0..0x2000 {
        let mut h = Sha256::new();
        h.update(&state);
        h.update(&salt);
        state = h.finalize().into();
    }
    let key = state;

    println!("Key: {}", hex::encode(&key));

    let mut data: Vec<u8> = Vec::new();
    file.read_to_end(&mut data)?;

    println!("\nDecrypting...");
    data = decrypt_aes256_cbc_pcks7(&data[..data.len()-32 /* skip HMAC tag at end */], &key, &iv.try_into().unwrap())?;

    let output_path = Path::new(&app_ctx.output_dir).join("decrypted.pkg");
    fs::create_dir_all(&app_ctx.output_dir)?;
    let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;       
    out_file.write_all(&data)?;
    println!("Saved decrypted file as decrypted.pkg\n");

    //run nvt pkg extraction into same directory
    let r_out_file = File::open(&output_path)?;
    let in_ctx: AppContext = AppContext { 
        input: InputTarget::File(r_out_file), 
        output_dir: app_ctx.output_dir.clone(), 
        options: app_ctx.options,
        keys: app_ctx.keys,
    };
    if let Some(result) = is_nvt_timg_pkg_file(&in_ctx)? {
        extract_nvt_timg_pkg(&in_ctx, result)?;
    }

    Ok(())
}
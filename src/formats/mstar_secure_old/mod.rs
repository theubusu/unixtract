mod include;
use std::any::Any;
use crate::{AppContext, InputTarget};

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::decrypt_aes128_ecb;
use crate::formats::mstar::{extract_mstar, is_mstar_file};
use include::*;

pub struct MstarSecureCtx {
    dec_footer: Vec<u8>,
}

pub fn is_mstar_secure_old_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let file_size = file.metadata()?.len();
    if file_size < 128 {
        return Ok(None);
    }
    let enc_footer = common::read_file(&file, file_size - 128, 128)?;
    let dec_key = app_ctx.keys.get_key_as_arr::<16>("MSTAR_DEFAULT_UPGRADE_KEY", 0)?;
    let dec_footer = decrypt_aes128_ecb(&dec_key, &enc_footer)?;

    if &dec_footer[0..8] == CHUNK_ID && &dec_footer[120..128] == CHUNK_END {
        Ok(Some(Box::new(MstarSecureCtx {dec_footer})))
    } else {
        Ok(None)
    }
}

pub fn extract_mstar_secure_old(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<MstarSecureCtx>().expect("Missing context");

    let hdr: ChunkFileFooter = Cursor::new(ctx.dec_footer).read_le()?;
    println!("Info -\nSegment size: {}\nFile data offset: {}\nFile data len: {}", hdr.segment_size, hdr.file_data_offset, hdr.file_data_len);

    let enc_data = common::read_file(&mut file, hdr.file_data_offset as u64, hdr.file_data_len as usize)?;
    
    println!("- Decrypting...");
    let dec_key = app_ctx.keys.get_key_as_arr::<16>("MSTAR_DEFAULT_UPGRADE_KEY", 0)?;
    let dec_data = decrypt_aes128_ecb(&dec_key, &enc_data)?;

    let output_path = Path::new(&app_ctx.output_dir).join("_decrypted.bin");
    fs::create_dir_all(&app_ctx.output_dir)?;
    let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;       
    out_file.write_all(&dec_data)?;

    //run standard mstar ext into same directory
    let r_out_file = File::open(&output_path)?;
    let in_ctx: AppContext = AppContext { 
        input: InputTarget::File(r_out_file), 
        output_dir: app_ctx.output_dir.clone(), 
        options: app_ctx.options,
        keys: app_ctx.keys,
    };

    //do check just in case and extract
    if let Some(result) = is_mstar_file(&in_ctx)? {
        extract_mstar(&in_ctx, result)?;
    } else {
        return Err("detection failed on decrypted data".into());                 
    }

    //delete decrypted file unless asked not to
    if !app_ctx.has_option("mstar_secure_old:keep_decrypted") {
        fs::remove_file(&output_path)?;
    }            

    Ok(())
}
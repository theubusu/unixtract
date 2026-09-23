mod include;
use std::any::Any;
use crate::{AppContext, InputTarget};

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::decrypt_aes256_cbc_nopad;
use crate::formats::mstar::{extract_mstar, is_mstar_file};
use include::*;

pub fn is_mstar_secure_new_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let chunk_id_head = common::read_file(&file, 0x500, 8)?;
    let chunk_id_end = common::read_file(&file, 0x500+120, 8)?;
    if chunk_id_head == CHUNK_ID && chunk_id_end == CHUNK_END {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_mstar_secure_new(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    // 0x0      signature               0x100
    // 0x100    header_version          0x200
    // 0x300    header_image_offset     0x200
    // 0x500    header_chunk_info       0x80
    // 0x580    signature               0x100

    file.seek(SeekFrom::Start(0x500))?;
    let chunk_info: ChunkInfo = file.read_le()?;
    println!("Info -\nSegment size: {}\nFile data offset: {}\nFile data len: {}",
            chunk_info.segment_size, chunk_info.file_data_offset, chunk_info.file_data_len);

    //get sample for key test
    let start_enc = common::read_file(&mut file, chunk_info.file_data_offset as u64, 0x80)?;
    let mut key: Option<[u8;32]> = None;
    for (name, keys) in app_ctx.keys.get_collection("MSTAR_SECURE")? {
        let ckey: [u8; 32] = keys.first().unwrap().as_slice().try_into().unwrap();
        let dec = decrypt_aes256_cbc_nopad(&start_enc, &ckey, &[0u8;16])?;

        let looks_like_script = dec.iter()
            .position(|&c| c == b'\n')
            .map(|p| dec[p + 1..].is_ascii())
            .unwrap_or(false);

        if dec.is_ascii() || looks_like_script {
            println!("\nUsing key: {}", name);
            key = Some(ckey);
            break;
        }
    }
    let key = if let Some(_key) = key {
        _key
    } else {
        return Err("No matching key found".into());
    };

    let segment_count = (chunk_info.file_data_len + chunk_info.segment_size - 1) / chunk_info.segment_size;
    println!("Segment count: {}", segment_count);

    let mut iv: [u8; 16] = [0u8; 16];

    fs::create_dir_all(&app_ctx.output_dir)?;
    let output_path = Path::new(&app_ctx.output_dir).join("_decrypted.bin");
    let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;
    out_file.seek(SeekFrom::Start(chunk_info.file_data_offset as u64))?;    //keep the same offset in decrypted file

    for i in 0..segment_count {
        //handle last block
        let size = if i == segment_count-1 && (chunk_info.file_data_len % chunk_info.segment_size) < chunk_info.segment_size {
            chunk_info.file_data_len % chunk_info.segment_size
        } else {
            chunk_info.segment_size
        };
        println!("  decrypting segment {}/{} (size: {})...", i+1, segment_count, size);

        let mut segment = common::read_exact(&mut file, size as usize)?;
        //iv is updated to the last 16 bytes of the encrypted segment, save it before decrypting
        let _iv = &segment[segment.len() - 16..].to_vec();

        segment = decrypt_aes256_cbc_nopad(&segment, &key, &iv)?;
        out_file.write_all(&segment)?;

        //update iv
        iv = _iv.as_slice().try_into().unwrap();
    }

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

    Ok(())
}

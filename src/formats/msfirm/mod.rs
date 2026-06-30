mod include;
use std::any::Any;
use crate::AppContext;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;

use crate::utils::common;
use include::*;

struct MsFirmCtx {
    key_name: String,
    key: [u8; 64]
}

pub fn is_msfirm_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 0x80)?;
    if header.len() != 0x80 {return Ok(None)};
    //check hash for all keys
    for (key_name, keys) in app_ctx.keys.get_collection("MSFIRM")? {
        let key: [u8; 64] = keys.first().unwrap().as_slice().try_into().unwrap();
        let mut hash_data = header[..108].to_vec();
        hash_data.extend_from_slice(&[0u8; 20]);
        if calc_hash(&key, &hash_data) == header[108..] {
            return Ok(Some(Box::new(MsFirmCtx { key_name: key_name.to_string(), key })));
        }
    }
    Ok(None)
}

pub fn extract_msfirm(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<MsFirmCtx>().expect("Missing context");

    println!("Using key: {}", ctx.key_name);

    //read and parse content table
    let content_enc = common::read_file(&mut file, 0x80, 0x5000)?;
    let content_dec = decrypt_sha(&ctx.key, &content_enc);
    opt_dump_dec_hdr(app_ctx, &content_dec, "content")?;
    let content = ContentDat::parse(&common::string_from_bytes(&content_dec))?;

    println!("\nFile info -\nData size: {}\nFiles count: {}", content.datasize, content.total_num);

    for entry in content.files {
        println!("\n({}/{}) - {}, Offset: {}, Size: {}, Encrypt: {}",
                entry.fnum+1, content.total_num, entry.name, entry.offset, entry.size, entry.encrypt);

        //skip headers
        let data_offset = entry.offset + ((entry.fnum +2)*0x80);
        let mut data = common::read_file(&mut file, data_offset as u64, entry.size as usize)?;
        if entry.encrypt {
            println!("- Decrypting...");
            data = decrypt_sha(&ctx.key, &data);
        }

        let output_path = Path::new(&app_ctx.output_dir).join(entry.name);
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");
    }
 
    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::compression::decompress_zlib;
use include::*;

pub fn is_spf1_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let key= app_ctx.keys.get_key_as_arr::<32>("SPF1", 0)?;

    let iv = common::read_file(&file, 0, 16)?;
    let hdr = common::read_file(&file, 16, 16)?;
    let dec_hdr = decrypt_aes256_cbc_cts(&key, &iv.try_into().unwrap(), &hdr)?;

    if dec_hdr.starts_with(b"SPF1") {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_spf1(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let key= app_ctx.keys.get_key_as_arr::<32>("SPF1", 0)?;
    let iv = common::read_exact(&mut file, 16)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    println!("Decrypting data...");
    data = decrypt_aes256_cbc_cts(&key, &iv.try_into().unwrap(), &data)?;

    let mut data_rdr = Cursor::new(data);
    let hdr: Spf1Header = data_rdr.read_be()?;

    println!("\nFile info -\nData size: {}\nUnpacked size: {}\nCompression type: {}\nSignature type: {}\n",
            hdr.data_size, hdr.unpacked_size, hdr.compression_type, hdr.signature_type);

    if hdr.signature_type != 0 {
        return Err("unknown signature type".into());
    }
    if hdr.compression_type != 0 && hdr.compression_type != 1 {
        return Err("unknown compression type".into());
    }

    let mut packed_data = common::read_exact(&mut data_rdr, hdr.data_size as usize)?;
    if hdr.compression_type == 1 {  //zlib compession
        println!("Decompressing data...");
        packed_data = decompress_zlib(&packed_data)?;
    }

    fs::create_dir_all(&app_ctx.output_dir)?;
    let output_path = Path::new(&app_ctx.output_dir).join("firmware.tar");
    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
    out_file.write_all(&packed_data)?;

    Ok(())
}
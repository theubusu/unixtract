mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes256_cbc_nopad};
use crate::utils::compression::{decompress_bzip, decompress_gzip, decompress_xz};
use include::*;

struct NvtTimgPkgCtx {
    pkg_format_version: PkgFormatVer,
}

pub fn is_nvt_timg_pkg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header_magic = common::read_file(&file, 0, 12)?;
    if header_magic == b"TIMGPKGVER40" {
        Ok(Some(Box::new(NvtTimgPkgCtx {pkg_format_version: PkgFormatVer::PkgVer40})))
    } else if header_magic == b"TIMGPKGVER30" {
        Ok(Some(Box::new(NvtTimgPkgCtx {pkg_format_version: PkgFormatVer::PkgVer30})))
    } else {
        Ok(None)
    }
}

pub fn extract_nvt_timg_pkg(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<NvtTimgPkgCtx>().expect("Missing context");
   
    let header: TIMGHeader = file.read_le()?;
    println!("File info:\nFormat version: {:?}\nData size: {}", ctx.pkg_format_version, header.flen);

    //position after header + data size
    let end = file.stream_position()? + header.flen as u64;

    let pp_table_hdr: PPHeader = file.read_le()?;
    if &pp_table_hdr.sign != b"PPCH" {
        return Err("invalid PP Cache table header signature".into());
    }

    println!("PP Cache table:");
    for i in 0..25 {
        let pp_table_ent: PPEntry = file.read_le()?;
        if pp_table_ent.valid != 1 {
            break;
        };
        println!("#{} - Name: {}, Device: {}, Offset: {}", i+1, pp_table_ent.name(), pp_table_ent.dev_path(), pp_table_ent.offset);
    }

    file.seek(SeekFrom::Start(0x720))?;

    let mut pimg_i = 0;
    while file.stream_position()? < end {
        pimg_i += 1;

        let pimg: PIMG = file.read_le()?;
        if &pimg.sign != b"PIMG" {
            return Err("invalid PIMG magic".into());
        }

        println!("\n#{} - {}, Size: {}, Dev: {}, Compression: {}, Param: {}",
                pimg_i, pimg.img_name(), pimg.flen, pimg.dev_path(), pimg.comp_type(), pimg.txt_param());

        let mut data = common::read_exact(&mut file, pimg.flen as usize)?;

        if ctx.pkg_format_version == PkgFormatVer::PkgVer40 {   //pkg ver 3.0 is not encrypted
            println!("- Decrypting...");

            //decrypt only aligned data, rest is plain
            let align_size = pimg.flen as usize & !0xF;
            let iv = app_ctx.keys.get_key_as_arr::<16>("NVT_FW40_IMG_ENC_IV", 0)?;
            let decrypted= if app_ctx.has_option("nvt_timg_pkg:use_v2_key") {   //cannot detect if v2 key is used, have to specify manually
                let key = app_ctx.keys.get_key_as_arr::<32>("NVT_FW40_IMG_ENC_V2_KEY", 0)?;
                decrypt_aes256_cbc_nopad(&data[..align_size], &key, &iv)?

            } else {
                let key = app_ctx.keys.get_key_as_arr::<16>("NVT_FW40_IMG_ENC_KEY", 0)?;
                decrypt_aes128_cbc_nopad(&data[..align_size], &key, &iv)?
            };

            data[..align_size].copy_from_slice(&decrypted);
        }
    
        if pimg.comp_type() == "gzip" && data.starts_with(b"\x1F\x8B") { //additionally check for gzip header, because sometimes its deceptive
            println!("-- Decompressing gzip...");
            data = decompress_gzip(&data)?;

        } else if pimg.comp_type() == "xz" {
            println!("-- Decompressing xz...");
            data = decompress_xz(&data)?;
        
        } else if pimg.comp_type() == "bzip2" {
            println!("-- Decompressing bzip...");
            data = decompress_bzip(&data)?;

        } else if pimg.comp_type() == "none" || pimg.comp_type() == "" {
        } else {
            println!("-- Warning: unsupported compression type, saving stored data!");
        }

        fs::create_dir_all(&app_ctx.output_dir)?;
        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", pimg.img_name()));
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");

    }

    Ok(())
}   
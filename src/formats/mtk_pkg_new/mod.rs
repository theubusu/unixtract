mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::global::opt_dump_dec_hdr;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::keys;
use crate::formats::mtk_pkg::lzhs::{decompress_mtk_to_file};
use crate::formats::mtk_pkg::include::{Header, PartEntry, MTK_HEADER_MAGIC, MTK_META_MAGIC, MTK_META_PAD_MAGIC};
use include::*;

pub struct MtkPkgNewContext {
    matching_key_name: String,
    matching_key_key: [u8; 16],
    matching_key_iv: [u8; 16],
    decrypted_header: Vec<u8>,
}

pub fn is_mtk_pkg_new_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let encrypted_header = common::read_file(&file, 0, HEADER_SIZE)?;
    for (key_hex, iv_hex, name) in keys::MTK_PKG_CUST {
        let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
        let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
        let try_decrypt = decrypt_aes128_cbc_nopad(&encrypted_header, &key_array, &iv_array)?;

        if &try_decrypt[4..12] == MTK_HEADER_MAGIC {    
            return Ok(Some(Box::new(MtkPkgNewContext {
                matching_key_name: name.to_string(),
                matching_key_key: key_array,
                matching_key_iv: iv_array,
                decrypted_header: try_decrypt
            })));
        }
    }

    Ok(None)
}

pub fn extract_mtk_pkg_new(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<MtkPkgNewContext>().expect("Missing context");

    let file_size = file.metadata()?.len();

    //the key was founf, and header was decrypted at detection stage so we can reuse
    println!("Using key {}", ctx.matching_key_name);
    let key_array = ctx.matching_key_key;
    let iv_array = ctx.matching_key_iv;
    let header = ctx.decrypted_header;
    opt_dump_dec_hdr(app_ctx, &header, "header")?;

    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {        
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        if !part_entry.is_valid() {
            break
        }

        println!("\n#{} - {}, Size: {}{} {}", 
                part_n, part_entry.name(), part_entry.size, if part_entry.is_compressed() {" [COMPRESSED]"} else {""}, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize + 48)?;
        
        if part_entry.size == 0 {
            println!("- Empty entry, skipping!");
            continue
        }

        let mut out_data;
        if part_entry.is_encrypted() {
            println!("- Decrypting...");
            //data aligned to 16 bytes is AES encrypted. the remaining unaligned data is XORed with the key
            let align_len = data.len() & !15;
            let (aes_enc, xor_tail) = data.split_at(align_len);
            out_data = decrypt_aes128_cbc_nopad(aes_enc, &key_array, &iv_array)?;
            for (i, &b) in xor_tail.iter().enumerate() {
                out_data.push(b ^ key_array[i % key_array.len()]);
            }
        } else {
            out_data = data;
        }

        //strip iMtK thing and get version
        let extra_header_len = if &out_data[48..52] == MTK_META_MAGIC {
            let imtk_len = u32::from_le_bytes(out_data[52..56].try_into().unwrap());
            if &out_data[56..60] != MTK_META_PAD_MAGIC {
                let version_len = u32::from_le_bytes(out_data[56..60].try_into().unwrap());
                let version = common::string_from_bytes(&out_data[60..60 + version_len as usize]);
                println!("- Version: {}", version);
            }
            imtk_len + 8
        } else {
            0
        };
        
        let fin_data = &out_data[48 + extra_header_len as usize..];
        
        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", part_entry.name()));
        fs::create_dir_all(&app_ctx.output_dir)?;

        if part_entry.is_compressed() {
            match decompress_mtk_to_file(&fin_data, &output_path) {
                Ok(()) => {
                    println!("-- Decompressed Successfully, Saved file!");
                    continue
                },
                Err(e) => {
                    eprintln!("Failed to decompress partition!, Error: {}. Saving compressed data...", e);
                }
            }
        }

        let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;
        out_file.write_all(&fin_data)?;
        println!("-- Saved file!");
    }

    Ok(())
}
pub mod include;
pub mod lzhs;
mod huffman_tables;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::keys;
use lzhs::{decompress_lzhs_fs_file2file};
use include::*;

pub struct MtkPkgContext {
    is_philips_variant: bool,
    decrypted_header: Vec<u8>,
}

pub fn is_mtk_pkg_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let mut encrypted_header = common::read_file(&file, 0, HEADER_SIZE)?;
    let mut header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV)?;
    if &header[4..12] == MTK_HEADER_MAGIC {
        Ok(Some(Box::new(MtkPkgContext { is_philips_variant: false, decrypted_header: header})))
    } else {
        // try for philips which has additional 128 bytes at beginning
        encrypted_header = common::read_file(&file, PHILIPS_EXTRA_HEADER_SIZE as u64, HEADER_SIZE)?;
        header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV)?;
        if &header[4..12] == MTK_HEADER_MAGIC {
            Ok(Some(Box::new(MtkPkgContext { is_philips_variant: true, decrypted_header: header })))
        } else {
            Ok(None)

        }
    }
}

pub fn extract_mtk_pkg(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<MtkPkgContext>().expect("Missing context");

    let file_size = file.metadata()?.len();
    let header = ctx.decrypted_header;
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    if ctx.is_philips_variant {
        file.seek(SeekFrom::Start(HEADER_SIZE as u64 + PHILIPS_EXTRA_HEADER_SIZE as u64))?;
    } else {
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    }

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {        
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        if !part_entry.is_valid() {break};

        println!("\n#{} - {}, Size: {}{} {}", 
                part_n, part_entry.name(), part_entry.size, if part_entry.is_compressed() {" [COMPRESSED]"} else {""}, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize + CRYPTED_HEADER_SIZE)?;
        
        if part_entry.size == 0 {
            println!("- Empty entry, skipping!");
            continue
        }

        let mut out_data;
        if part_entry.is_encrypted() {
            let mut matching_key: Option<[u8; 16]> = None;
            let mut matching_iv: Option<[u8; 16]> = None;

            let crypted_header = &data[..CRYPTED_HEADER_SIZE];

            // try decrypting with vendor magic repeated 4 times (works for most)
            let mut key = [0u8; 16];
            for i in 0..4 {
                key[i * 4..(i + 1) * 4].copy_from_slice(&hdr.vendor_magic_bytes);
            }
            let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key, &HEADER_IV)?;
            if try_decrypt.starts_with(MTK_RESERVED_MAGIC) {
                println!("- Decrypting with 4xVendor magic...");
                matching_key = Some(key);
                matching_iv = Some(HEADER_IV);

            } else {
                //try decrypting with one of custom keys
                for (key_hex, iv_hex, name) in keys::MTK_PKG_CUST {
                    let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
                    let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
                    let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key_array, &iv_array)?;

                    if try_decrypt.starts_with(MTK_RESERVED_MAGIC) {
                        println!("- Decrypting with key {}...", name);
                        matching_key = Some(key_array);
                        matching_iv = Some(iv_array);
                        break
                    }
                }
            }

            if matching_key.is_some() && matching_iv.is_some() {
                let (key_array, iv_array) = (matching_key.unwrap(), matching_iv.unwrap());
                //data aligned to 16 bytes is AES encrypted. the remaining unaligned data is XORed with the key
                let align_len = data.len() & !15;
                let (aes_enc, xor_tail) = data.split_at(align_len);
                out_data = decrypt_aes128_cbc_nopad(aes_enc, &key_array, &iv_array)?;
                for (i, &b) in xor_tail.iter().enumerate() {
                    out_data.push(b ^ key_array[i % key_array.len()]);
                }
            } else {
                println!("- Failed to decrypt data!");
                continue
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
        
        //for compressed part create temp file
        let output_path = Path::new(&app_ctx.output_dir).join(part_entry.name() + if part_entry.is_compressed() {".lzhs"} else {".bin"});
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).read(true)/* for lzhs */.create(true).open(&output_path)?;
        out_file.write_all(&out_data[CRYPTED_HEADER_SIZE + extra_header_len as usize..])?;

        if part_entry.is_compressed() {
            let lzhs_out_path = Path::new(&app_ctx.output_dir).join(part_entry.name() + ".bin");
            match decompress_lzhs_fs_file2file(&out_file, lzhs_out_path) {
                Ok(()) => {
                    println!("- Decompressed Successfully!");
                    //after successfull decompression remove the temporary .lzhs file
                    fs::remove_file(&output_path)?;
                },
                Err(e) => {
                    eprintln!("Failed to decompress partition!, Error: {}. Saving compressed data...", e);
                    //if the decompression is not successfull leave out compressed data.
                }
            }   
        }

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
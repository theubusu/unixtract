mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_zimage_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let zimg_magic = common::read_file(&file, 0x2000, 8)?;
    if zimg_magic == b"Zimg\xa5\x96\x92\x98" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_zimage(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let do_remove_oob = app_ctx.has_option("zimage:remove_oob");

    file.seek(SeekFrom::Start(0x2000))?;
    let hdr: ZimageHeader = file.read_be()?;

    println!("Image info -\nImage name: {}\nFile size: {}\nFormat version: {}\nRelease version: {}\nModel: {}\nPage size: {}\nSpare size: {}\nModule Count: {}",
            hdr.image_name(), hdr.file_total_size, hdr.format_version, hdr.release_version, hdr.model, hdr.page_size, hdr.spare_size, hdr.module_count);

    for (i, module) in hdr.modules.iter().enumerate() {
        println!("\n#{}/{} - {}, Type: {}, Sub-type: {}, File offset: {}, File size: {}, Flash offset: {}, Flash size: {}, Partition size: {}{} {}",
            i+1, hdr.module_count, module.module_name(), module.module_type as char, module.subtype, module.data_offset, module.stored_size, module.flash_offset, module.flash_size, module.partition_size,
            if module.is_compressed() {" [COMPRESSED]"} else {""}, if module.is_encrypted() {"[ENCRYPTED]"} else {""}
        );

        if module.flash_size == 0 {
            println!("- Not flashed, skipping...");
            continue
        }

        let mut data = common::read_file(&mut file, module.data_offset.into(), module.stored_size as usize)?;

        if module.is_encrypted() && module.is_compressed() {    //in-update decryption is only done when module is also compressed
            // the encryption is done by hardware DMA, cannot be replicated (or at least easily)
            println!("- WARNING: Cannot decrypt data. Saving encrypted data!");
        } else {
            if module.is_compressed() {
                println!("- Decompressing...");
                // do decompress LZMA chunks
                let mut out = Vec::new();
                let mut cur = Cursor::new(&data);
                while out.len() < module.flash_size as usize {
                    lzma_rs::lzma_decompress(&mut cur, &mut out)?;
                    //println!("pos= {} len={}", cur.position(), out.len());
                    cur.seek(SeekFrom::Start(((cur.position() + 3) / 4) * 4))?; //each chunk is padded to 4b boundary
                }
                data = out;
            }

            //do removing OOB
            if do_remove_oob {
                if data.len() % (hdr.page_size + hdr.spare_size) as usize == 0 {
                    println!("- Removing OOB...");
                    let mut j = 0u32;
                    data.retain(|_| {
                        let keep = j % (hdr.spare_size + hdr.page_size) < hdr.page_size;
                        j += 1;
                        keep
                    });

                } else {
                    println!("- This data is not suitable for OOB removal");
                }
            }
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", i+1, module.module_name().strip_prefix("/").unwrap_or(&module.module_name())));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;         
        out_file.write_all(&data)?;
        println!("-- Saved file!");
    }

    Ok(())
}
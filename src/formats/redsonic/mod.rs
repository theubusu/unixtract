mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_redsonic_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let magic = common::read_file(&file, 0, 8)?;
    if magic == b"\xAD\xBA\xBB\xAC\xB0\xB1\xB6\xBC" {   //inverted b"REDSONIC"
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_redsonic(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let mut hdrbuf = common::read_exact(&mut file, 0x100)?;
    hdrbuf.iter_mut().for_each(|b| *b = !*b);   //invert decode (=xor with 0xFF)
    let hdr: RedsonicHeader = Cursor::new(hdrbuf).read_le()?;

    println!("Version info: {}", hdr.version_info());

    let sect: [(&str, bool, u32); 5] = [
        ("bootloader", hdr.has_bootloader==1, hdr.bootloader_size),
        ("kernel", hdr.has_kernel==1, hdr.kernel_size),
        ("rootfs", hdr.has_rootfs==1, hdr.rootfs_size),
        ("para0", hdr.has_para0==1, hdr.para0_size),
        ("splash", hdr.has_splash==1, hdr.splash_size),
    ];
    let total = sect.iter().filter(|(_, b, _)| *b).count();
    
    let mut p = 0;
    for (name, present, size) in sect {
        if !present {
            continue
        }
        println!("\n#{}/{} - {}, Size: {}", p+1, total, name, size);
        let mut data = common::read_exact(&mut file, size as usize)?;
        data.iter_mut().for_each(|b| *b = !*b); //also data decode

        fs::create_dir_all(&app_ctx.output_dir)?;
        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", name));
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
        p += 1;
    }

    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_bdl_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"ibdl" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_bdl(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: BdlHeader = file.read_le()?;

    println!("File info:\nPackage count: {}\nDate: {}\nManufacturer: {}\nModel: {}\nVersion: {}\nInfo: {}",
                header.pkg_count, header.date(), header.manufacturer(), header.model(), header.version(), header.info());

    let mut pkgs: Vec<PkgListEntry> = Vec::new();

    for _i in 0..header.pkg_count {
        let pkg_entry: PkgListEntry = file.read_le()?;
        //println!("Package {} - Offset: {}, Size: {}", i + 1, pkg_entry.offset, pkg_entry.size);
        pkgs.push(pkg_entry);
    }

    for (i, pkg) in pkgs.iter().enumerate() {
        file.seek(SeekFrom::Start(pkg.offset))?;
        let pkg_header: PkgHeader = file.read_le()?;
        println!("\nPackage ({}/{}) - Name: {}, Version: {}, Entry Count: {}, Manufacturer: {}, Offset: {}, Size: {}", 
                i + 1, header.pkg_count, pkg_header.name(), pkg_header.version(), pkg_header.entry_count, pkg_header.manufacturer(), pkg.offset, pkg.size);

        let mut pkg_entries: Vec<PkgEntry> = Vec::new();

        for _i in 0..pkg_header.entry_count {
            let pkg_entry: PkgEntry = file.read_le()?;
            pkg_entries.push(pkg_entry);
        }

        let pkg_folder = Path::new(&app_ctx.output_dir).join(pkg_header.name());
        fs::create_dir_all(&pkg_folder)?;

        for (i, pkg_entry) in pkg_entries.iter().enumerate() {
            println!("- Entry {}/{} - Name: {}, Offset: {}, Size: {}", 
                    i + 1, pkg_header.entry_count, pkg_entry.name(), pkg_entry.offset, pkg_entry.size);

            let calc_offset = pkg.offset + pkg_entry.offset; 
            let data = common::read_file(&file, calc_offset, pkg_entry.size as usize)?;

            let output_path = Path::new(&pkg_folder).join(pkg_entry.name());
            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            
            out_file.write_all(&data)?;

            println!("-- Saved file!");

        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
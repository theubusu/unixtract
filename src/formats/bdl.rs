use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "bdl", detector_func: is_bdl_file, extractor_func: extract_bdl }
}

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

#[derive(BinRead)]
struct BdlHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //ibdl
    #[br(count = 8)] _file_version: Vec<u8>,
    _unk1: u32,
    pkg_count: u32,
    #[br(count = 12)] _unk2: Vec<u8>,
    #[br(count = 256)] date_bytes: Vec<u8>,
    #[br(count = 256)] manufacturer_bytes: Vec<u8>,
    #[br(count = 256)] model_bytes: Vec<u8>,
    #[br(count = 9)] _unk3: Vec<u8>,
    #[br(count = 256)] version_bytes: Vec<u8>,
    #[br(count = 1280)] info_bytes: Vec<u8>,
}
impl BdlHeader {
    fn date(&self) -> String {
        common::string_from_bytes(&self.date_bytes)
    }
    fn manufacturer(&self) -> String {
        common::string_from_bytes(&self.manufacturer_bytes)
    }
    fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    fn info(&self) -> String {
        common::string_from_bytes(&self.info_bytes)
    }
}

#[derive(BinRead)]
struct PkgListEntry {
    offset: u64,
    size: u64,
}

#[derive(BinRead)]
struct PkgHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //ipkg
    #[br(count = 12)] _unk1: Vec<u8>,
    entry_count: u32,
    #[br(count = 12)] _unk2: Vec<u8>,
    #[br(count = 256)] version_bytes: Vec<u8>,
    #[br(count = 256)] manufacturer_bytes: Vec<u8>,
    #[br(count = 256)] name_bytes: Vec<u8>,
    #[br(count = 285)] _unk3: Vec<u8>,
}
impl PkgHeader {
    fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    fn manufacturer(&self) -> String {
        common::string_from_bytes(&self.manufacturer_bytes)
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct PkgEntry {
    #[br(count = 256)] name_bytes: Vec<u8>,
    offset: u64,
    size: u64,
    _crc32: u32,
}
impl PkgEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

pub fn is_bdl_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let header = common::read_file(app_ctx.file, 0, 4)?;
    if header == b"ibdl" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_bdl(app_ctx: &AppContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file;
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

        let pkg_folder = Path::new(app_ctx.output_dir).join(pkg_header.name());
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
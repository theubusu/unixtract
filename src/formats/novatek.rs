use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "novatek", detector_func: is_novatek_file, extractor_func: extract_novatek }
}

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write};

use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    version_major: u32,
    version_minor: u32,
    _unused: u32,
    #[br(count = 16)] firmware_name_bytes: Vec<u8>,
    data_size: u32,
    #[br(count = 16)] _md5_checksum: Vec<u8>, //data checksum
    part_count: u32,
    _data_start_offset: u32,
    #[br(count = 128)] _signature: Vec<u8>,
    _header_checksum: u32, //CRC32, calculated with the field set to 0
}
impl Header {
    fn firmware_name(&self) -> String {
        common::string_from_bytes(&self.firmware_name_bytes)
    }
}

#[derive(BinRead)]
struct PartEntry {
    id: u32,
    size: u32,
    offset: u32,
    #[br(count = 16)] _md5_checksum: Vec<u8>,
}

pub fn is_novatek_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"NFWB" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_novatek(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: Header = file.read_le()?;
    println!("File info:\nFirmware name: {}\nVersion: {}.{}\nData size: {}\nPart count: {}",
            header.firmware_name(), header.version_major, header.version_minor, header.data_size, header.part_count);

    let mut entries: Vec<PartEntry> = Vec::new();
    for _i in 0..header.part_count {
        let part: PartEntry = file.read_le()?;
        entries.push(part);
    }

    let mut e_i = 0;
    for entry in &entries {
        e_i += 1;
        println!("\n({}/{}) - ID: {}, Offset: {}, Size: {}", e_i, entries.len(), entry.id, entry.offset, entry.size);

        let data = common::read_file(&file, entry.offset as u64, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", e_i, entry.id));

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;       
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
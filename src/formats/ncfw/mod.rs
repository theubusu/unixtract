mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_ncfw_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header_magic = common::read_file(&file, 0, 4)?;
    if header_magic == b"NCFW" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_ncfw(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: NcfwHeader = file.read_le()?;

    println!("File info -\nFile size: {}\nHeader size: {}\nData size: {}\nEncryption type: {}\nSignature size: {}\n",
            header.total_size, header.header_size, header.data_size, header.encryption_type, header.signature_size);

    let mut data = common::read_file(&mut file, header.header_size as u64, header.data_size as usize)?;
    data = match header.encryption_type {
        0 => {
            println!("Decrypting data (method 0)...");
            decrypt0(&data)
        },
        1 => {
            println!("Decrypting data (method 1)...");
            decrypt1(&data)
        },
        _ => {
            return Err("unknown encryption type".into());
        }
    };

    let mut nca_i = 0;
    let mut data_reader = Cursor::new(data);
    while data_reader.stream_position()? < header.data_size as u64 {
        let nca_header: NcaHeader = data_reader.read_be()?;
        if &nca_header.magic != b"\xAF\xAF\x9C\x9C" {
            return Err("invalid NCA magic".into());
        }

        println!("\n#{} - Address: 0x{:x}, Type: {}, Version: {:02x}.{:02x}, Date: {:x}, Size: {}, Data size: {}",
                nca_i+1, nca_header.dest_address, nca_header.nca_type, nca_header.version_major, nca_header.version_minor, nca_header.date, nca_header.size, nca_header.data_out_size);

        let entry_data = common::read_exact(&mut data_reader, nca_header.size as usize - 0x40)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_0x{:x}.bin", nca_i, nca_header.dest_address));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;        
        out_file.write_all(&entry_data)?;

        println!("- Saved file!");

        nca_i += 1;
    }

    Ok(())
}
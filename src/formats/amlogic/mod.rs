mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::sparse::unsparse_to_file;
use include::*;

pub fn is_amlogic_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    
    let header = common::read_file(&file, 8, 4)?;
    if header == b"\x56\x19\xB5\x27" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_amlogic(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    file.seek(SeekFrom::Start(0))?;
    let header: ImageHeader = file.read_le()?;

    println!("File info -\nImage size: {}\nItem align size: {}\nItem count: {}\nFormat version: {}", 
            header.image_size, header.item_align_size, header.item_count, header.version);

    if header.version != 2 {
        return Err("Unsupported format version! (Only 2 is supported right now)".into());
    }

    let mut items: Vec<ItemEntry> = Vec::new();

    for _i in 0..header.item_count {
        let item: ItemEntry = file.read_le()?;
        items.push(item);
    }

    for (i, item) in items.iter().enumerate() {
        println!("\n({}/{}) - {}, Type: {}, Offset: {}, Size: {} {}",
                i+1, header.item_count, item.name(), item.item_type(), item.offset_in_image, item.item_size, if item.is_sparse() {"[SPARSE]"} else {""});

        if item.item_type() == "VERIFY" { //verify item is SHA1 of partition item
            let sum_bytes = common::read_file(&file, item.offset_in_image, item.item_size as usize)?;
            let sum = common::string_from_bytes(&sum_bytes);
            println!("- Checksum for {}: {}", item.name(), sum);

        } else {
            let data = common::read_file(&file, item.offset_in_image, item.item_size as usize)?;
 
            let extension = if item.item_type() == "PARTITION" {"img"} else {&item.item_type()};
            let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.{}", item.name(), extension));
            fs::create_dir_all(&app_ctx.output_dir)?;
            
            if item.is_sparse() {
                println!("- Unsparsing...");
                unsparse_to_file(&data, output_path)?;
                println!("-- Saved file!");
                continue

            } else {
                let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                out_file.write_all(&data)?;
                println!("- Saved file!");
            } 
            
        }
    }

    Ok(())
}
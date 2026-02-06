use std::any::Any;
use crate::{InputTarget, AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "amlogic", detector_func: is_amlogic_file, extractor_func: extract_amlogic }
}

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::sparse::{unsparse_to_file};

#[derive(BinRead)]
struct ImageHeader {
    _crc32: u32,
    version: u32,
    #[br(count = 4)] _magic_bytes: Vec<u8>, //56 19 B5 27
    image_size: u64,
    item_align_size: u32,
    item_count: u32,
    #[br(count = 36)] _reserved: Vec<u8>,
}

#[derive(BinRead)]
struct ItemEntry {
    _item_id: u32,
    file_type: u32,
    _current_offset_in_item: u64,
    offset_in_image: u64,
    item_size: u64,
    #[br(count = 256)] item_type_bytes: Vec<u8>,
    #[br(count = 256)] name_bytes: Vec<u8>,
    _verify: u32,
    _is_backup_item: u16,
    _backup_item_id: u16,
    #[br(count = 24)] _reserved: Vec<u8>,
}
impl ItemEntry {
    fn item_type(&self) -> String {
        common::string_from_bytes(&self.item_type_bytes)
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn is_sparse(&self) -> bool {
        self.file_type == 254
    }
}

pub fn is_amlogic_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match &app_ctx.input {InputTarget::File(f) => f, InputTarget::Directory(_) => return Ok(None)};
    
    let header = common::read_file(&file, 8, 4)?;
    if header == b"\x56\x19\xB5\x27" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_amlogic(app_ctx: &AppContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match &app_ctx.input {InputTarget::File(f) => f, InputTarget::Directory(_) => return Err("Extractor expected file, not directory".into())};

    file.seek(SeekFrom::Start(0))?;
    let header: ImageHeader = file.read_le()?;

    println!("File info -\nImage size: {}\nItem align size: {}\nItem count: {}\nFormat version: {}", 
            header.image_size, header.item_align_size, header.item_count, header.version);

    if header.version != 2 {
        println!("\nSorry, this format version is not yet supported!");
        return Ok(());
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

    println!("\nExtraction finished!");
    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub struct SlpContext {
    variant: SlpVariant,
}

pub fn is_slp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header = common::read_file(&file, 0, 4)?;
    if header == b"SLP\x00" {
        let check = common::read_file(&file, 44, 1)?[0];
        let variant: SlpVariant;
        if check == 0 || check == 1 {
            variant = SlpVariant::Old
        }
        else if check == 5 || check == 6 { //?
            variant = SlpVariant::Old2
        }
        else {
            variant = SlpVariant::New
        }

        Ok(Some(Box::new(SlpContext {variant})))
    } else {
        Ok(None)
    }
}

pub fn extract_slp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<SlpContext>().expect("Missing context");

    let meta_header: CommonMetaHeader = file.read_le()?;
    println!("File info:\nType: {:?}\nProject name: {}\nFirmware Version: {}\nFirmware Version(USER): {}",
            ctx.variant, meta_header.project_name(), meta_header.firmware_version(), meta_header.user_version());

    let num_image;
    let mut snapshot_entry_offset: Option<u32> = None;
    if ctx.variant == SlpVariant::New {
        let meta_header_ext: MetaHeaderExtNew = file.read_le()?;
        if meta_header_ext.snapshot_included == 0x01 {
            println!("Snapshot Image: Included");
            println!("S/S Img. Board Version: {}", meta_header_ext.snapshot_board_version())
        } else {
            println!("Snapshot Image: Excluded");
        }
        num_image = meta_header_ext.num_image;
    }
    else if ctx.variant == SlpVariant::Old {
        let meta_header_ext: MetaHeaderExtOld = file.read_le()?;
        if meta_header_ext.snapshot_included == 0x01 {
            println!("Snapshot Image: Included");
            println!("Snapshot Image offset: {}", meta_header_ext.snapshot_entry_offset);
            snapshot_entry_offset = Some(meta_header_ext.snapshot_entry_offset);
        } else {
            println!("Snapshot Image: Excluded");
        }
        num_image = 5; //hardcoded for old variant
    }
    else if ctx.variant == SlpVariant::Old2 {
        let meta_header_ext: MetaHeaderExtNew = file.read_le()?;
        //snapshot fields of new meta_header_ext are not used in this case
        num_image = meta_header_ext.num_image;
    }
    else {
        return Err("invalid slp variant".into());
    }

    let mut entries: Vec<EntryCommon> = Vec::new();

    for _i in 0..num_image {
        let entry: EntryCommon = file.read_le()?;
        if ctx.variant == SlpVariant::New {
            let _version_bytes = common::read_exact(&mut file, 8)?;
        }
        entries.push(entry);
    }

    //push additional snapshot entry
    if let Some(offset) = snapshot_entry_offset {
        file.seek(SeekFrom::Start(offset as u64))?;
        let entry: EntryCommon = file.read_le()?;
        entries.push(entry);
    }

    for (i, entry) in entries.iter().enumerate() {
        println!("\n({}/{}) - Offset: {}, Size: {}, Magic: 0x{:02X}", i+1, &entries.len(), entry.offset, entry.size, entry.magic);

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", i+1));

        file.seek(SeekFrom::Start(entry.offset.into()))?;
        let data = common::read_exact(&mut file, entry.size as usize)?;
        
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;         
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_epk1_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let epk2_magic = common::read_file(&file, 12, 4)?; //for epk2b
    let epak_magic = common::read_file(&file, 0, 4)?;
    if epak_magic == b"epak" && epk2_magic != b"EPK2" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_epk1(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    //check type of epk1
    let epk1_type;
    let init_pak_count_bytes = common::read_file(&file, 8, 4)?;
    let init_pak_count = u32::from_le_bytes(init_pak_count_bytes.try_into().unwrap());

    if init_pak_count > 256 {
        println!("\nBig endian EPK1 detected.");
        epk1_type = "be";
    } else if init_pak_count < 33 {
        println!("\nLittle endian EPK1 detected.");
        epk1_type = "le";
    } else {
        println!("\nUnknown EPK1 variant!");
        return Ok(());
    }

    file.seek(SeekFrom::Start(0))?;

    let mut paks: Vec<Pak> = Vec::new();

    if epk1_type == "be" {
        let header: CommonHeader = file.read_be()?;

        for _i in 0..10 { //header can fit max 10 pak entries
            let pak: Pak = file.read_be()?;
            if pak.offset == 0 && pak.size == 0 {
                continue;
            }
            paks.push(Pak { offset: pak.offset, size: pak.size });
        }
        assert!(header.pak_count as usize == paks.len(), "Paks count in header({}) does not match the amount of non empty pak entries({})!", header.pak_count, paks.len());

        let version = common::read_exact(&mut file, 4)?;

        println!("EPK info -\nData size: {}\nPak count: {}\nVersion: {:02x?}.{:02x?}.{:02x?}",
                header.file_size, header.pak_count, version[1], version[2], version[3]);

    } else if epk1_type == "le" {
        let header: CommonHeader = file.read_le()?;

        //this is to make an odd variant with 32 max pak entries work
        let header_size_bytes = common::read_file(&file, 12, 4)?; //offset of first entry, can be treated as header size
        let header_size = u32::from_le_bytes(header_size_bytes.try_into().unwrap());
        let max_pak_count = (header_size - 48) / 8; //header size minus common header + ota id (48) divide by size of pak entry (8). 
        assert!(max_pak_count < 128, "Unreasonable calculated pak count {}!!", max_pak_count);

        for _i in 0..max_pak_count {
            let pak: Pak = file.read_le()?;
            if pak.offset == 0 && pak.size == 0 {
                continue;
            }
            paks.push(Pak { offset: pak.offset, size: pak.size });
        }
        assert!(header.pak_count as usize == paks.len(), "Paks count in header({}) does not match the amount of non empty pak entries({})!", header.pak_count, paks.len());

        let version = common::read_exact(&mut file, 4)?;

        let ota_id_bytes = common::read_exact(&mut file, 32)?;
        let ota_id = common::string_from_bytes(&ota_id_bytes);

        println!("EPK info -\nData size: {}\nHeader size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}", 
                header.file_size, header_size, header.pak_count, ota_id, version[2], version[1], version[0]);
    }

    for (i, pak) in paks.iter().enumerate() {
        file.seek(SeekFrom::Start(pak.offset as u64))?;
        let pak_header: PakHeader = if epk1_type == "be" {file.read_be()?} else {file.read_le()?};

        println!("\n({}/{}) - {}, Offset: {}, Size: {}, Platform: {}", 
                i + 1, paks.len(), pak_header.pak_name(), pak.offset, pak_header.image_size, pak_header.platform_id());

        let data = common::read_exact(&mut file, pak_header.image_size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(pak_header.pak_name() + ".bin");
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;        
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }
    
    println!("\nExtraction finished!");

    Ok(())
}
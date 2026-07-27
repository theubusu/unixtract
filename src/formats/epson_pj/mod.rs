mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_epson_pj_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let enc_hdr = common::read_file(&file, 0, 48)?;
    let (key, iv) = app_ctx.keys.get_double_key_as_arr::<8, 8>("EPSONPJ")?;
    let dec_hdr = decrypt_des_cbc(&enc_hdr, &key, &iv)?;

    let entry: Entry = Cursor::new(dec_hdr).read_le()?;

    //dumb checks
    let file_size = file.metadata()?.len() as u32;
    if  entry.id < 255 && entry.id != 0 &&
        entry.offset < 1024 && entry.offset != 0 && //first entry should have small offset
        entry.size < file_size && entry.size != 0 &&
        entry.name().is_ascii() 
    {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_epson_pj(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    //decrypt entire file
    let mut enc_data = Vec::new();
    file.read_to_end(&mut enc_data)?;

    let (key, iv) = app_ctx.keys.get_double_key_as_arr::<8, 8>("EPSONPJ")?;
    println!("Decrypting...");
    let dec_data = decrypt_des_cbc(&enc_data, &key, &iv)?;

    let mut data_reader = Cursor::new(dec_data);
    let mut entries: Vec<Entry> = Vec::new();

    for _ in 0..32 /* just a guess */ {
        let entry: Entry = data_reader.read_le()?;
        if entry.size == 0 && entry.offset == 0 {
            break
        }
        entries.push(entry);
    }

    for (i, entry) in entries.iter().enumerate() {
        println!("\n#{} - {}, ID: {}, Offset: {}, Size: {}", i+1, entry.name(), entry.id, entry.offset, entry.size);

        data_reader.seek(SeekFrom::Start(entry.offset as u64))?;
        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.name()));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;          
        out_file.write_all(&data)?;

        println!("- Saved file!");
      
        //do inner partitions
        let mut inner_data_reader = Cursor::new(data.as_slice());
        let mut partitions: Vec<(u32, u32)> = Vec::new();

        if data.starts_with(b"\x14\xEF\xCD\xAB") {
            println!("- Partition layout 1 detected");
            for _ in 0..32 {
                let part_entry: PartitionEntry1 = inner_data_reader.read_le()?;
                if part_entry.magic != 0xABCDEF14 {break}; 
                partitions.push((part_entry.offset, part_entry.size));
            }

        } else if data.starts_with(b"\x18\xDE\xDC\xAB") || data.starts_with(b"\x15\xDE\xDC\xAB"){
            println!("- Partition layout 2 detected");
            let part_hdr: PartitionHeader2 = inner_data_reader.read_le()?;
            println!("- Header size: {}, Data size: {}", part_hdr.header_size, part_hdr.data_size);
            for _ in 0..((part_hdr.header_size-16)/16) {
                let partition: PartitionEntry2 = inner_data_reader.read_le()?;
                if partition.size == 0 {break};
                partitions.push((partition.offset + part_hdr.header_size, partition.size));
            }

        } else if data.len() > 1040 {
            let part_hdr: PartitionHeader3 = inner_data_reader.read_le()?;
            if  (part_hdr.pad1 == 0 && part_hdr.pad2 == 0) &&
                ((part_hdr.data_size + part_hdr.header_size) == data.len() as u32 ||
                 (part_hdr.data_size + part_hdr.header_size + 64) == data.len() as u32 /* sig ver */ )
            {
                println!("- Partition layout 3 detected");
                for _ in 0..((part_hdr.header_size-1040)/16) {
                    let partition: PartitionEntry2 = inner_data_reader.read_le()?;
                    if partition.size == 0 {break};
                    partitions.push((partition.offset + part_hdr.header_size, partition.size));
                }
            }
        }

        for (i, (offset, size)) in partitions.iter().enumerate() {
            println!("-- #{}, Offset: {}, Size: {}", i+1, offset, size);

            inner_data_reader.seek(SeekFrom::Start(*offset as u64))?;
            let data = common::read_exact(&mut inner_data_reader, *size as usize)?;

            let output_dir = Path::new(&app_ctx.output_dir).join(format!("_{}.bin", entry.name()));
            fs::create_dir_all(&output_dir)?;
            let output_path = Path::new(&output_dir).join(format!("{}.bin", i+1));
            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;          
            out_file.write_all(&data)?;

            println!("--- Saved file!");
        }
    }
 
    Ok(())
}
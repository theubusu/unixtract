mod include;

use std::any::Any;
use crate::AppContext;
use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::collections::HashSet;
use binrw::BinReaderExt;

use crate::utils::common;
use crate::formats::sddl_sec::include::*;
use crate::utils::compression::decompress_zlib;
use include::*;

pub fn is_sdboot_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 32).expect("Failed to read from file.");
    let deciph_header = decipher(&header);

    let chk = deciph_header.iter().all(|&b| {
        matches!(b,
            b'0'..=b'9'
        )
    });

    if chk {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn get_file(mut in_file: &File, search_file_name: &str, file_list: &Vec<FileEntry>, key: &KeyEntry) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file_idx = file_list.iter().position(|entry| entry.name == search_file_name)
        .ok_or_else(|| format!("Requested file {} was not found!", search_file_name))?;  
    let entry = &file_list[file_idx];
    
    in_file.seek(SeekFrom::Start(entry.offset))?;
    let enc_data = common::read_exact(&mut in_file, entry.size)?;
    let dec_data = KeyEntry::decrypt(key, &enc_data)?;
    let mut data_rdr = Cursor::new(dec_data);

    let sub_hdr: EntrySubHeader = data_rdr.read_be()?;
    let data = common::read_exact(&mut data_rdr, sub_hdr.size() as usize)?;
    
    Ok(data)
}

pub fn extract_sdboot(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let mut secfile_hdr_reader = Cursor::new(decipher(&common::read_exact(&mut file, 32)?));
    let secfile_header: SdbootSecHeader = secfile_hdr_reader.read_be()?;

    let key_id = secfile_header.key_id();
    if key_id != 0 && key_id != 1 {
        return Err(format!("Invalid sdboot key_id! got {} but must be 0 or 1", key_id).into());
    }
    let key: KeyEntry = KeyEntry::AES(KEYS[key_id as usize]);

    println!("File info -\nKey ID: {}\nFile count: {}", secfile_header.key_id(), secfile_header.num_files());

    //create file list
    let mut file_list: Vec<FileEntry> = Vec::new();  
    for _i in 0..secfile_header.num_files() {
        let mut entry_header_reader = Cursor::new(KeyEntry::decrypt(&key, &common::read_exact(&mut file, 64)?)?);
        let entry_header: SdbootEntryHeader = entry_header_reader.read_be()?;

        let offset = file.stream_position()?;
        //println!("File: {} - Offset: {}, Size: {}", entry_header.name(), offset, entry_header.file_size());

        file_list.push( FileEntry { name: entry_header.name(), size: entry_header.file_size(), offset });
        file.seek(SeekFrom::Current(entry_header.file_size() as i64))?;
    }

    fs::create_dir_all(&app_ctx.output_dir)?;
    let mut processed_image_files: HashSet<String> = HashSet::new(); //so processed image files are not extracted later

    //check for "IMGFILE.TXT" , if it exists, we will extract NAND/NOR images. (old route?)
    if let Ok(imgfile_data) = get_file(&file, "IMGFILE.TXT", &mut file_list, &key) {
        //example-  nand: nandall.img
        let imgfile_text = common::string_from_bytes(&imgfile_data);
        let mut s = imgfile_text.trim_end().split(": ");
        let target = s.next().unwrap();     //"nand"
        let target_filename = s.next().unwrap();    //"nandall.img"

        println!("\nSaving {} to {}...", target, target_filename);
        let output_path = Path::new(&app_ctx.output_dir).join(&target_filename);
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(&output_path)?;

        //get info file
        let infofile_name = format!("{}.inf", target_filename.split(".").next().unwrap());  //"nandall.inf"
        let infofile = get_file(&file, &infofile_name, &file_list, &key)?;
        let mut infofile_reader = Cursor::new(infofile);
        let info_header: InfoListHeader = infofile_reader.read_le()?;
        for i in 0..info_header.part_count {
            let part_entry: InfoListEntry = infofile_reader.read_le()?;
            println!("- ({}/{}) Size: {}, Compressed?: {}", i+1, info_header.part_count, part_entry.out_size, part_entry.is_compressed());

            let part_file_name = format!("{}{:02x}", target_filename, i); //not sure what happens if it goes over 255
            let mut part_data = get_file(&file, &part_file_name, &file_list, &key)?;

            if part_entry.is_ciphered() {
                println!("-- Deciphering...");
                part_data = decipher(&part_data);
            }

            if part_entry.is_compressed() {
                println!("-- Decompressing...");
                part_data = decompress_zlib(&part_data)?;
            }

            out_file.write_all(&part_data)?;
            processed_image_files.insert(part_file_name);
        }

        println!("--- Saved file!");
    }

    //extract the rest of the files
    for entry in file_list.iter() {
        if processed_image_files.contains(&entry.name) {
            continue;
        }

        println!("\nFile: {} - Size: {}", entry.name, entry.size);

        let file_data = get_file(&file, &entry.name, &file_list, &key)?;
        let output_path = Path::new(&app_ctx.output_dir).join(&entry.name);
        let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
        out_file.write_all(&file_data)?;
        println!("- Saved file!");
    }

    Ok(())
}
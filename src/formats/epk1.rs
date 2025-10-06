use std::fs::File;
use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};

use crate::common;

pub fn is_epk1_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    let header_string = String::from_utf8_lossy(&header);

    if header_string == "epak"{
        true
    } else {
        false
    }
}

struct Pak {
    offset : u32,
    size : u32,
}

pub fn extract_epk1(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {

    //check type of epk1
    let epk1_type;
    let init_pak_count_bytes = common::read_file(&file, 8, 4)?;
    let init_pak_count = u32::from_le_bytes(init_pak_count_bytes.try_into().unwrap());

    if init_pak_count > 256 {
        println!("Big endian EPK1 detected.");
        epk1_type = "be";
    } else if init_pak_count < 21 {
        println!("Little endian EPK1 detected.");
        epk1_type = "le";
    } else {
        //println!("EPK1(new) detected.");
        //epk1_type = "new";
        println!("Not supported!");
        return Ok(());
    }

    file.seek(SeekFrom::Start(0))?;

    let mut paks: Vec<Pak> = Vec::new();

    if epk1_type == "be" {
        //epak magic
        let _epak = common::read_exact(&mut file, 4)?;

        //file size
        let file_size_bytes = common::read_exact(&mut file, 4)?;
        let file_size = u32::from_be_bytes(file_size_bytes.try_into().unwrap());

        //pak count
        let pak_count_bytes = common::read_exact(&mut file, 4)?;
        let pak_count = u32::from_be_bytes(pak_count_bytes.try_into().unwrap());

        for _i in 0..10 { //header can fit max 10 pak entries
            let pak_offset_bytes = common::read_exact(&mut file, 4)?;
            let pak_offset = u32::from_be_bytes(pak_offset_bytes.try_into().unwrap());

            let pak_size_bytes = common::read_exact(&mut file, 4)?;
            let pak_size = u32::from_be_bytes(pak_size_bytes.try_into().unwrap());

            if pak_offset == 0 && pak_size == 0 {
                continue;
            }

            paks.push(Pak { offset: pak_offset, size: pak_size });
        }

        assert!(pak_count as usize == paks.len(), "Paks count in header does not match the amount of non empty pak entries!");

        let version = common::read_exact(&mut file, 4)?;

        println!("EPK info:\nFile size: {}\nPak count: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\n",
                file_size, pak_count, version[1], version[2], version[3]);

    } else if epk1_type == "le" {
        //epak magic
        let _epak = common::read_exact(&mut file, 4)?;

        //file size
        let file_size_bytes = common::read_exact(&mut file, 4)?;
        let file_size = u32::from_le_bytes(file_size_bytes.try_into().unwrap());

        //pak count
        let pak_count_bytes = common::read_exact(&mut file, 4)?;
        let pak_count = u32::from_le_bytes(pak_count_bytes.try_into().unwrap());

        for _i in 0..20 { //header can fit max 20 pak entries
            let pak_offset_bytes = common::read_exact(&mut file, 4)?;
            let pak_offset = u32::from_le_bytes(pak_offset_bytes.try_into().unwrap());

            let pak_size_bytes = common::read_exact(&mut file, 4)?;
            let pak_size = u32::from_le_bytes(pak_size_bytes.try_into().unwrap());

            if pak_offset == 0 && pak_size == 0 {
                continue;
            }

            paks.push(Pak { offset: pak_offset, size: pak_size });
        }

        assert!(pak_count as usize == paks.len(), "Paks count in header does not match the amount of non empty pak entries!");

        let version = common::read_exact(&mut file, 4)?;

        let ota_id_bytes = common::read_exact(&mut file, 32)?;
        let ota_id = common::string_from_bytes(&ota_id_bytes);

        println!("EPK info:\nFile size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\n", 
                file_size, pak_count, ota_id, version[2], version[1], version[0]);
    }

    for (i, pak) in paks.iter().enumerate() {
            let pak_name_bytes = common::read_file(&file, pak.offset as u64, 4)?;
            let pak_name = common::string_from_bytes(&pak_name_bytes);

            let pak_actual_size_bytes = common::read_file(&file, pak.offset as u64 + 4, 4)?;
            let pak_actual_size;
            if epk1_type == "be" {
                pak_actual_size = u32::from_be_bytes(pak_actual_size_bytes.try_into().unwrap());
            } else {
                pak_actual_size = u32::from_le_bytes(pak_actual_size_bytes.try_into().unwrap());
            }

            let pak_platform_bytes = common::read_file(&file, pak.offset as u64 + 8, 15)?;
            let pak_platform = common::string_from_bytes(&pak_platform_bytes);

            let data = common::read_file(&file, pak.offset as u64, pak.size as usize)?;

            println!("- Pak {}: {}, Offset: {}, Size: {}, Platform: {}", i + 1, pak_name, pak.offset, pak.size, pak_platform);

            let output_path = Path::new(&output_folder).join(pak_name + ".bin");

            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(output_path)?;
            
            out_file.write_all(&data[128..pak_actual_size as usize + 128])?;

            println!("-- Saved file!");
        }
    
    println!("\nExtraction finished!");

    Ok(())
}
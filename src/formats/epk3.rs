use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom, Cursor};

use crate::common;
use crate::keys;
use crate::formats::epk::{decrypt_aes_ecb_auto, find_key};

pub fn extract_epk3(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(128))?; //inital signature

    let stored_header = common::read_exact(&mut file, 1584)?; //max header size
    let header: Vec<u8>;

    let mut new_type = false;

    let matching_key: Option<Vec<u8>>;
    println!("Finding key...");

    // find the key, knowing that the header should start with "EPK3"
    if let Some((key_name, key_bytes)) = find_key(&keys::EPK3, &stored_header, b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;

    //try for new format epk3 where theres an additional 128byte signature at the beginning
    } else if let Some((key_name, key_bytes)) = find_key(&keys::EPK3, &stored_header[128..], b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;
        new_type = true;

    } else {
        println!("No valid key found!");
        return Ok(());
    }

    let signature_size = if new_type {256} else {128};
    let extra_segment_size = if new_type {4} else {0};

    let matching_key_bytes = matching_key.as_ref().unwrap();

    //parse header
    let mut hdr_reader = Cursor::new(header);

    if new_type {let _signature = common::read_exact(&mut hdr_reader, 128)?;};

    let _epk3 = common::read_exact(&mut hdr_reader, 4)?; //EPK3 magic

    let version = common::read_exact(&mut hdr_reader, 4)?;

    let ota_id_bytes = common::read_exact(&mut hdr_reader, 32)?;
    let ota_id = common::string_from_bytes(&ota_id_bytes);

    let package_info_size_bytes = common::read_exact(&mut hdr_reader, 4)?;
    let package_info_size = u32::from_le_bytes(package_info_size_bytes.try_into().unwrap());

    println!("\nEPK info:\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\nPackage Info size: {}\n", 
                ota_id, version[3], version[2], version[1], package_info_size);
    //

    let _versions = common::read_exact(&mut file, 36)?;

    let _signature = common::read_exact(&mut file, signature_size)?;

    //PKG INFO
    let pkg_info_encrypted = common::read_exact(&mut file, package_info_size as usize)?;
    let pkg_info = decrypt_aes_ecb_auto(matching_key_bytes, &pkg_info_encrypted)?;

    let mut pkg_info_reader = Cursor::new(pkg_info);

    let package_info_list_size_b = common::read_exact(&mut pkg_info_reader, 4)?;
    let package_info_list_size = u32::from_le_bytes(package_info_list_size_b.try_into().unwrap());

    let package_info_count_b = common::read_exact(&mut pkg_info_reader, 4)?;
    let package_info_count = u32::from_le_bytes(package_info_count_b.try_into().unwrap());

    println!("Package info list size: {}\nPackage info count: {}", 
                package_info_list_size, package_info_count);

    if new_type {let _unknown = common::read_exact(&mut pkg_info_reader, 4)?;}; //uncertain if this is only in new type, but i think it is

    while (pkg_info_reader.position() as usize) < pkg_info_reader.get_ref().len() {
        let segment = common::read_exact(&mut pkg_info_reader, 324)?;

        let package_name_b = &segment[8..136];
        let package_name = common::string_from_bytes(&package_name_b);

        let package_size_b = &segment[296..300];
        let package_size = u32::from_le_bytes(package_size_b.try_into().unwrap());

        //Package segment info
        let segment_index_b = &segment[308..312];
        let mut segment_index = u32::from_le_bytes(segment_index_b.try_into().unwrap());

        let segment_count_b = &segment[312..316];
        let segment_count = u32::from_le_bytes(segment_count_b.try_into().unwrap());

        let segment_size_b = &segment[316..320];
        let mut segment_size = u32::from_le_bytes(segment_size_b.try_into().unwrap());
        //

        println!("\nPak - {}, Size: {}, Segments: {}",
                package_name, package_size, segment_count);
        
        for i in 0..segment_count {
            if i > 0 {
                let segment = common::read_exact(&mut pkg_info_reader, 324)?;

                let segment_index_b = &segment[308..312];
                segment_index = u32::from_le_bytes(segment_index_b.try_into().unwrap());

                let segment_size_b = &segment[316..320];
                segment_size = u32::from_le_bytes(segment_size_b.try_into().unwrap()); 
            }   
            
            println!("- Segment {}/{}, Size: {}", segment_index + 1, segment_count, segment_size);

            let _signature = common::read_exact(&mut file, signature_size)?;

            let encrypted_data = common::read_exact(&mut file, segment_size as usize + extra_segment_size)?;
            let out_data = decrypt_aes_ecb_auto(matching_key_bytes, &encrypted_data)?;

            let output_path = Path::new(&output_folder).join(package_name.clone() + ".bin");

            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(output_path)?;

            out_file.write_all(&out_data[extra_segment_size..])?;

            println!("-- Saved to file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
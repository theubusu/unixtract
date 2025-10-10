use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom, Cursor};

use binrw::{BinRead, BinReaderExt};

use crate::common;
use crate::keys;
use crate::formats::epk::{decrypt_aes_ecb_auto, find_key};

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    file_size: u32,
	pak_count: u32,
	#[br(count = 4)] _epk2_magic: Vec<u8>,
	#[br(count = 4)] version: Vec<u8>,
	#[br(count = 32)] ota_id_bytes: Vec<u8>,
}
impl Header {
    fn ota_id(&self) -> String {
        common::string_from_bytes(&self.ota_id_bytes)
    }
}

#[derive(BinRead)]
struct PakEntry {
    offset: u32,
	size: u32,
	#[br(count = 4)] name_bytes: Vec<u8>,
	#[br(count = 4)] _version: Vec<u8>,
	segment_size: u32,
}
impl PakEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

pub fn is_epk2_file(file: &File) -> bool {
    let header = common::read_file(&file, 128, 4).expect("Failed to read from file.");
    if header == b"epak" {
        true
    } else {
        false
    }
}

struct Pak {
    offset: u32,
    size: u32,
    name: String,
}

pub fn extract_epk2(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(128))?; //inital signature

    let stored_header = common::read_exact(&mut file, 1584)?; //max header size
    let header;

    let mut matching_key: Option<Vec<u8>> = None;

    //check if header is encrypted
    let epak = &stored_header[0..4]; // epak magic
    if epak == b"epak" {
        println!("Header is not encrypted.");
        header = stored_header;
    } else {
        println!("Header is encrypted...");
        println!("\nFinding key...");
        //find the key, knowing that the header should start with "epak"
        if let Some((key_name, key_bytes)) = find_key(&keys::EPK2, &stored_header, b"epak")? {
            println!("Found valid key: {}", key_name);
            matching_key = Some(key_bytes);
            header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;
        } else {
            println!("No valid key found!");
            return Ok(());
        }    
    }
    //parse header
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("\nEPK info:\nFile size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\n", 
                hdr.file_size, hdr.pak_count, hdr.ota_id(), hdr.version[3], hdr.version[2], hdr.version[1]);
 
    let mut paks: Vec<Pak> = Vec::new();
    //parse paks in header
    for i in 0..hdr.pak_count {
        let pak: PakEntry = hdr_reader.read_le()?;

        println!("Pak {}: {}, offset: {}, size: {}, segment size: {}", i + 1, pak.name(), pak.offset + 128, pak.size, pak.segment_size);

        paks.push(Pak { offset: pak.offset + 128, size: pak.size, name: pak.name() });
    }

    let mut signature_count = 0;
    //extract paks
    for (pak_n, pak) in paks.iter().enumerate() {     
        let actual_offset = pak.offset + (128 * signature_count);
        
        file.seek(SeekFrom::Start(actual_offset as u64))?;

        let _signature = common::read_exact(&mut file, 128)?;
        signature_count += 1;

        let encrypted_header = common::read_exact(&mut file, 128)?;

        //the file's header was not encrypted so we dont have the key yet
        if matching_key.is_none() {
            println!("\nFinding key...");
            //find the key, knowing that the header should start with with the paks name
            if let Some((key_name, key_bytes)) = find_key(&keys::EPK2, &encrypted_header, pak.name.as_bytes())? {
                println!("Found correct key: {}", key_name);
                matching_key = Some(key_bytes);
            } else {
                println!("No valid key found!");
                return Ok(());
            }
        }

        let matching_key_bytes = matching_key.as_ref().unwrap();

        let header = decrypt_aes_ecb_auto(&matching_key_bytes, &encrypted_header)?;

        let segment_count = u32::from_le_bytes(header[84..88].try_into().unwrap());
        let mut segment_size = u32::from_le_bytes(header[88..92].try_into().unwrap());

        println!("\nPak {}/{} - {}, Size: {}, Segments: {}", pak_n + 1, paks.len(), pak.name, pak.size, segment_count);

        for i in 0..segment_count {
            // for first segment we already read the header so skip doing that for it
            if i > 0 {
                let _signature = common::read_exact(&mut file, 128)?;
                signature_count += 1;

                let encrypted_header = common::read_exact(&mut file, 128)?;
                let header = decrypt_aes_ecb_auto(&matching_key_bytes, &encrypted_header)?;
                segment_size = u32::from_le_bytes(header[88..92].try_into().unwrap());
            }

            let actual_segment_size = 
            // check if this is the last segment and not the last PAK
            if i == segment_count - 1 && pak_n < paks.len() - 1 {
                // calculate distance to next PAK
                let next_pak_offset = &paks[pak_n + 1].offset + (128 * signature_count);
                let current_pos = file.stream_position()?;
                let distance = next_pak_offset - current_pos as u32;
                
                // if distance less than segment size, use the distance as actual size
                if distance < segment_size {
                    distance
                } else {
                    segment_size
                }

            } else {
                segment_size
            };

            let segment_data = common::read_exact(&mut file, actual_segment_size as usize)?;
            let out_data = decrypt_aes_ecb_auto(&matching_key_bytes, &segment_data)?;

            println!("- Segment {}/{}, size: {}", i + 1, segment_count, actual_segment_size);

            let output_path = Path::new(&output_folder).join(pak.name.clone() + ".bin");

            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(output_path)?;

            out_file.write_all(&out_data)?;

            println!("-- Saved to file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
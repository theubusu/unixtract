use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom, Cursor};

use aes::Aes128;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

use crate::common;

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

static KEYS: &[(&str, &str)] = &[
    ("Saturn7/BCM3556", "2F2E2D2C2B2A29281716151413121110"),
    ("new BCM35230", "6856A0482475A8B41728A35474810203"),
    ("mtk5369 - Mediatek GP4", "7184C9C428D03C445188234D5A827196"),
    ("mtk5398 (a2) - Mediatek NetCast 4/4.5", "385A992430196A8C44F1985823C01440"),
];

fn find_key<'a>(data: &[u8], expected_magic: &[u8]) -> Result<Option<(&'a str, Vec<u8>)>, Box<dyn std::error::Error>> {
    for (name, key_hex) in KEYS {
        let key_bytes = hex::decode(key_hex)?;
        let decrypted = match decrypt_aes128_ecb(&key_bytes, data) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if decrypted.starts_with(expected_magic) {
            return Ok(Some((name, key_bytes)));
        }
    }
    Ok(None)
}

type Aes128EcbDec = Decryptor<Aes128>;

fn decrypt_aes128_ecb(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_array: [u8; 16] = key.try_into()?;
    let mut decryptor = Aes128EcbDec::new(&key_array.into());
    let mut buffer = ciphertext.to_vec();

    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    
    Ok(buffer)
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
        if let Some((key_name, key_bytes)) = find_key(&stored_header, b"epak")? {
            println!("Found valid key: {}", key_name);
            matching_key = Some(key_bytes);
            header = decrypt_aes128_ecb(matching_key.as_ref().unwrap(), &stored_header)?;
        } else {
            println!("No valid key found!");
            return Ok(());
        }    
    }
    //parse header
    let mut hdr_reader = Cursor::new(header);

    let _epk = common::read_exact(&mut hdr_reader, 4)?;

    let file_size_bytes = common::read_exact(&mut hdr_reader, 4)?;
    let file_size = u32::from_le_bytes(file_size_bytes.try_into().unwrap());

    let pak_count_bytes = common::read_exact(&mut hdr_reader, 4)?;
    let pak_count = u32::from_le_bytes(pak_count_bytes.try_into().unwrap());

    let _epk2 = common::read_exact(&mut hdr_reader, 4)?; // EPK2 magic

    let version = common::read_exact(&mut hdr_reader, 4)?;

    let ota_id_bytes = common::read_exact(&mut hdr_reader, 32)?;
    let ota_id = common::string_from_bytes(&ota_id_bytes);

    println!("\nEPK info:\nFile size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\n", 
                file_size, pak_count, ota_id, version[3], version[2], version[1]);
 
    let mut paks: Vec<Pak> = Vec::new();
    //parse paks in header
    for i in 0..pak_count {
        let offset_bytes = common::read_exact(&mut hdr_reader, 4)?;
        let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap()) + 128; //add 128 bytes of initial signature

        let size_bytes = common::read_exact(&mut hdr_reader, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        let name_bytes = common::read_exact(&mut hdr_reader, 4)?;
        let name = common::string_from_bytes(&name_bytes);

        let _version = common::read_exact(&mut hdr_reader, 4)?;

        let segment_size_bytes = common::read_exact(&mut hdr_reader, 4)?;
        let segment_size = u32::from_le_bytes(segment_size_bytes.try_into().unwrap());

        println!("Pak {}: {}, offset: {}, size: {}, segment size: {}", i + 1, name, offset, size, segment_size);

        paks.push(Pak { offset, size, name });
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
            if let Some((key_name, key_bytes)) = find_key(&encrypted_header, pak.name.as_bytes())? {
                println!("Found correct key: {}", key_name);
                matching_key = Some(key_bytes);
            } else {
                println!("No valid key found!");
                return Ok(());
            }
        }

        let matching_key_bytes = matching_key.as_ref().unwrap();

        let header = decrypt_aes128_ecb(&matching_key_bytes, &encrypted_header)?;

        let segment_count = u32::from_le_bytes(header[84..88].try_into().unwrap());
        let mut segment_size = u32::from_le_bytes(header[88..92].try_into().unwrap());

        println!("\nPak {}/{} - {}, Size: {}, Segments: {}", pak_n + 1, paks.len(), pak.name, pak.size, segment_count);

        for i in 0..segment_count {
            // for first segment we already read the header so skip doing that for it
            if i > 0 {
                let _signature = common::read_exact(&mut file, 128)?;
                signature_count += 1;

                let encrypted_header = common::read_exact(&mut file, 128)?;
                let header = decrypt_aes128_ecb(&matching_key_bytes, &encrypted_header)?;
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
            let out_data = decrypt_aes128_ecb(&matching_key_bytes, &segment_data)?;

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
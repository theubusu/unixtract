use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom};

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

    file.seek(SeekFrom::Start(128))?;

    //check if header is encrypted
    let epak = common::read_exact(&mut file, 4)?; // epak magic
    if epak == b"epak" {
        println!("Header is not encrypted.");
    } else {
        println!("Header is encrypted. Not supported yet");
        return Ok(());
    }

    let file_size_bytes = common::read_exact(&mut file, 4)?;
    let file_size = u32::from_le_bytes(file_size_bytes.try_into().unwrap());

    let pak_count_bytes = common::read_exact(&mut file, 4)?;
    let pak_count = u32::from_le_bytes(pak_count_bytes.try_into().unwrap());

    let _epk2 = common::read_exact(&mut file, 4)?; // EPK2 magic

    let version = common::read_exact(&mut file, 4)?;

    let ota_id_bytes = common::read_exact(&mut file, 32)?;
    let ota_id = common::string_from_bytes(&ota_id_bytes);

    println!("\nEPK info:\nFile size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}\n", 
                file_size, pak_count, ota_id, version[3], version[2], version[1]);
 
    let mut paks: Vec<Pak> = Vec::new();

    for i in 0..pak_count {
        let offset_bytes = common::read_exact(&mut file, 4)?;
        let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap()) + 128; //add 128 bytes of initial signature

        let size_bytes = common::read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        let name_bytes = common::read_exact(&mut file, 4)?;
        let name = common::string_from_bytes(&name_bytes);

        let _version = common::read_exact(&mut file, 4)?;

        let segment_size_bytes = common::read_exact(&mut file, 4)?;
        let segment_size = u32::from_le_bytes(segment_size_bytes.try_into().unwrap());

        println!("Pak {}: {}, offset: {}, size: {}, segment size: {}", i + 1, name, offset, size, segment_size);

        paks.push(Pak { offset, size, name });
    }

    // Saturn7/BCM3556
    //let key = "2F2E2D2C2B2A29281716151413121110";

    // new BCM35230
    let key = "6856A0482475A8B41728A35474810203";

    //mtk5369 - Mediatek GP4 - HE_DTV_GP4I_AFAAATAA
    //let key = "7184C9C428D03C445188234D5A827196";

    let key_bytes = hex::decode(key)?;

    let mut signature_count = 0;

    for (pak_n, pak) in paks.iter().enumerate() {
          
        let actual_offset = pak.offset + (128 * signature_count);
        
        file.seek(SeekFrom::Start(actual_offset as u64))?;

        let _signature = common::read_exact(&mut file, 128)?;
        signature_count += 1;

        let encrypted_header = common::read_exact(&mut file, 128)?;
        let header = decrypt_aes128_ecb(&key_bytes, &encrypted_header)?;

        let segment_count = u32::from_le_bytes(header[84..88].try_into().unwrap());
        let mut segment_size = u32::from_le_bytes(header[88..92].try_into().unwrap());

        println!("\nPak {}/{} - {}, Size: {}, Segments: {}", pak_n + 1, paks.len(), pak.name, pak.size, segment_count);

        for i in 0..segment_count {
            // for first segment we already read the header so skip doing that for it
            if i > 0 {
                let _signature = common::read_exact(&mut file, 128)?;
                signature_count += 1;

                let encrypted_header = common::read_exact(&mut file, 128)?;
                let header = decrypt_aes128_ecb(&key_bytes, &encrypted_header)?;
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
            let out_data = decrypt_aes128_ecb(&key_bytes, &segment_data)?;

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
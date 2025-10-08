use std::fs::{File};
use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::path::Path;
use std::io::{Cursor, Write};
use std::fs::{self, OpenOptions};

use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

use crate::common;
use crate::keys;

pub fn is_pfl_upg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 8).expect("Failed to read from file.");
    if header == b"2SWU3TXV" {
        true
    } else {
        false
    }
}

static AUTO_FWS: &[(&str, &str)] = &[
    ("Q5551", "q5551"),
    ("Q5553", "q5551"),
    ("Q554E", "q5551"),
    ("Q554M", "q5551"),
    ("QF1EU", "qf1eu"),
    ("QF2EU", "qf1eu"),
    ("Q591E", "q591e"),
    ("Q522E", "q522e"),
    ("Q582E", "q522e"),
    ("Q5481", "q5481"),
    ("Q5431", "q5431"),
];

type Aes256EcbDec = Decryptor<Aes256>;

fn decrypt_aes256_ecb(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_array: [u8; 32] = key.try_into()?;

    let mut decryptor = Aes256EcbDec::new(&key_array.into());
    let mut buffer = ciphertext.to_vec();

    for chunk in buffer.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    
    Ok(buffer)
}

pub fn extract_pfl_upg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = common::read_exact(&mut file, 8)?; //2SWU3TXV magic

    let header_size_bytes = common::read_exact(&mut file, 4)?;
    let header_size = u32::from_le_bytes(header_size_bytes.try_into().unwrap());

    let data_size_bytes = common::read_exact(&mut file, 4)?;
    let data_size = u32::from_le_bytes(data_size_bytes.try_into().unwrap());

    let _crc32 = common::read_exact(&mut file, 4)?;

    let mask_bytes = common::read_exact(&mut file, 4)?;
    let mask = u32::from_le_bytes(mask_bytes.try_into().unwrap());

    let _data_size_decompressed = common::read_exact(&mut file, 4)?;

    let _padding2 = common::read_exact(&mut file, 4)?;

    let description_bytes = common::read_exact(&mut file, 512)?;
    let description = common::string_from_bytes(&description_bytes);
    
    let signature = common::read_exact(&mut file, 128)?;

    let _ = common::read_exact(&mut file, 32)?; //unknown

    let version_bytes = common::read_exact(&mut file, header_size as usize - 704)?;
    let version = common::string_from_bytes(&version_bytes);

    println!("\nVersion: {}", version);
    println!("Description: \n{}", description);
    println!("Data size: {}", data_size);

    let decrypted_data;
    if (mask & 0x2000_0000) != 0 {
        println!("File is encrypted.");
        let mut key = None;
        let mut n_hex = None;

        //find key
        for (firmware, value) in AUTO_FWS {
            if version.starts_with(firmware) {
                key = Some(value);
                break;
            }
        }
        if key.is_none() {
            println!("Sorry, this firmware is not supported!");
            std::process::exit(1);
        }

        //get key
        for (prefix, value) in keys::PFLUPG {
            if key == Some(prefix) {
                n_hex = Some(value);
                break;
            }
        }

        let e_hex = "010001";

        let n = BigUint::from_bytes_be(&decode(n_hex.unwrap())?);
        let e = BigUint::from_bytes_be(&decode(e_hex)?);
        let pubkey = RsaPublicKey::new(n, e)?;

        let signature_int = BigUint::from_bytes_le(&signature);

        let decrypted_int = rsa::hazmat::rsa_encrypt(&pubkey, &signature_int)?;
        let decrypted = decrypted_int.to_bytes_le();

        let aes_key = &decrypted[20..52];
        println!("AES key: {}\n", hex::encode(aes_key));

        let encrypted_data = common::read_exact(&mut file, data_size as usize)?;
        println!("Decrypting data...");
        decrypted_data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
    } else {
        println!("File is not encrypted.");
        decrypted_data = common::read_exact(&mut file, data_size as usize)?;
    }

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        //file header
        let file_header = common::read_exact(&mut data_reader, 76)?;

        let file_name = common::string_from_bytes(&file_header[0..60]);

        let real_size = u32::from_le_bytes(file_header[60..64].try_into().unwrap());

        let stored_size = u32::from_le_bytes(file_header[64..68].try_into().unwrap());

        let _header_size = u32::from_le_bytes(file_header[68..72].try_into().unwrap());

        println!("\nFile: {}, Size: {}", file_name, real_size);

        let data = common::read_exact(&mut data_reader, stored_size as usize)?;

        let output_path = Path::new(&output_folder).join(file_name.trim_start_matches('/'));

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&data[..real_size as usize])?;

        println!("- Saved file!");
    }

    println!("\nExtraction finished!");
    
    Ok(())
}
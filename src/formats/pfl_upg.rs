use std::fs::{File};
use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::io::Cursor;

use aes::Aes256;
use ecb::cipher::{BlockDecryptMut, KeyInit};
use ecb::Decryptor;
use block_padding::NoPadding;

use crate::common;

pub fn is_pfl_upg_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 8).expect("Failed to read from file.");
    let header_string = String::from_utf8_lossy(&header);

    if header_string == "2SWU3TXV"{
        true
    } else {
        false
    }
}

fn decrypt_aes256_ecb_no_padding(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>{

    let mut cipher = Decryptor::<Aes256>::new_from_slice(key)?;
    let mut buf = ciphertext.to_vec();

    // decrypt in place
    for block in buf.chunks_mut(16) {
        cipher.decrypt_block_mut(block.into());
    }

    Ok(buf)
}

pub fn extract_pfl_upg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    //2SWU3TXV magic
    let _ = common::read_exact(&mut file, 8)?;

    //header size
    let _ = common::read_exact(&mut file, 4)?;

    //data size
    let data_size_bytes = common::read_exact(&mut file, 4)?;
    let data_size = u32::from_le_bytes(data_size_bytes.try_into().unwrap());
    println!("Data size: {}", data_size);

    //crc32
    let _ = common::read_exact(&mut file, 4)?;

    //mask??
    let _ = common::read_exact(&mut file, 4)?;

    //data size decompressed
    let _ = common::read_exact(&mut file, 4)?;

    //padding2?
    let _ = common::read_exact(&mut file, 4)?;

    //description
    let description_bytes = common::read_exact(&mut file, 512)?;
    let description = common::string_from_bytes(&description_bytes);
    println!("Description: \n{}", description);

    //signature
    let signature = common::read_exact(&mut file, 128)?;

    //unknown
    let _ = common::read_exact(&mut file, 32)?;

    //version string
    let version_bytes = common::read_exact(&mut file, 28)?;
    let version = common::string_from_bytes(&version_bytes);
    println!("Version: {}", version);

    //get aes key
    //QF1EU
    let n_hex = "ACD684155C7CCCB04372A8808514489FA9EE75D305987D1337420241FDBE0AE1F7CDFBB931C9D56C91D36F2CE79D222695B484FF42BCA12CE362C7C9ABBDEEC8E5D6107FADCF2D4DA5DF0693E13ACE54A18AEB21C051F6B62C075A1791985547C1CFF4FB5B6EA7E0A9405A1B2BB71EB89A9B209E0F62BF9794D673179C0E60F1";
    let e_hex = "010001";

    let n = BigUint::from_bytes_be(&decode(n_hex)?);
    let e = BigUint::from_bytes_be(&decode(e_hex)?);
    let pubkey = RsaPublicKey::new(n, e)?;

    let signature_int = BigUint::from_bytes_le(&signature);

    let decrypted_int = rsa::hazmat::rsa_encrypt(&pubkey, &signature_int)?;
    let decrypted = decrypted_int.to_bytes_le();

    let aes_key = &decrypted[20..52];
    println!("AES key: {}", hex::encode(aes_key));
    //end get aes key

    let encrypted_data = common::read_exact(&mut file, data_size as usize)?;
    println!("Decrypting data...");
    let decrypted_data = decrypt_aes256_ecb_no_padding(aes_key, &encrypted_data)?;

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        //file header
        let file_header = common::read_exact(&mut data_reader, 76)?;

        let file_name = common::string_from_bytes(&file_header[0..60]);
        println!("File: {}", file_name);

        let real_size = u32::from_le_bytes(file_header[60..64].try_into().unwrap());
        println!("- Real size: {}", real_size);

        let stored_size = u32::from_le_bytes(file_header[64..68].try_into().unwrap());
        println!("- Stored size: {}", stored_size);

        let header_size = u32::from_le_bytes(file_header[68..72].try_into().unwrap());
        println!("- Header size: {}", header_size);

        let _data = common::read_exact(&mut data_reader, stored_size as usize)?;
    }
    
    Ok(())
}
use std::fs::{File};
use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::path::Path;
use std::io::{Cursor, Write};
use std::fs::{self, OpenOptions};

use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

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

static KEYS: &[(&str, &str)] = &[
    ("q5551", "D7EE8ED11AC048ED225D4F5F53F8509E55C5D94256A703C79E4CA78AE93ECE1639FE466363AD962BD6D6DE0C46FD19F363687C1D8A21820740A6E7FF87F41C4900DCE1E26EC122E5D4DFA76BFC8F296816B8D0910325E9DC5CBCC9579CF15FC0253EF7CF4919B7613491A5D7BF75DC1888531C458967FD1CF64B33139550BAA5"),
    ("qf1eu", "ACD684155C7CCCB04372A8808514489FA9EE75D305987D1337420241FDBE0AE1F7CDFBB931C9D56C91D36F2CE79D222695B484FF42BCA12CE362C7C9ABBDEEC8E5D6107FADCF2D4DA5DF0693E13ACE54A18AEB21C051F6B62C075A1791985547C1CFF4FB5B6EA7E0A9405A1B2BB71EB89A9B209E0F62BF9794D673179C0E60F1"),
    ("q591e", "AFAF89062747CBB29343C4E4EA775E4CFDF5FAFCD92C9DD858A8725201BA54AB973BEFEE04EBF3046910FBBC78B10120AE16D80BA734931E97248BC6B1D4A909F087D37BC0A9C2210FF8A2BE44C00F31E4DD8713A364623637FF75EBBCE9D3A840DB67E0FA910F127F679496F6C21112E3E3AD4ACA459FDE1CC58E300682E6F9"),
    ("q522e", "C41BE92C212BAC76B48261E2A1704028287DD7E121C11DA25F709E864FBDC1BD8C7F226F57605A4B42D768CDD629AF9E54011A0967AFC2826331406FB1E90321620738526EA0BEA59F1A0E612AE891C396112F13531F423DF02F94D1C871429549F4D5B30D9CA3EFDCC6D7A96849F7C1788DE8FAAEDD36560337008DF06D612F"),
    ("q5481", "9E7DA389815251E82A84A1182807702E72A0B0E0FF707C8E73E2EA71F79D5FAAFFC6E0B90ED16E13A4289C78A7D3BDA90626162AAE169D7BE28D6A635585CC10639C4E312E288EB8F7C5A44518B7E8A26A45C5023C5078A972A4CC219CA020BAF524F7429257B7AD76E1B15390879064C6ED59CC1F20CC04EEC26C9CF7FC0727"),
    ("q5431", "C5FD937B301A5CEF4B6C25F187728C99636515D058895FEA469496E2B24907FC7721648841F8AE4C618E215673D0C029752FA970B6F9A7F48C9331293D3B1D43E4DFC7B52914973642CD3E4EE0AD11F5254505038F95CACE0DF21FC769B34E134435D88AB617D2981F66EF45BBC7796CFB1086C5D5672E837204991FE53BC1CF"),
];

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

    println!("Version: {}", version);
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
        for (prefix, value) in KEYS {
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
        println!("AES key: {}", hex::encode(aes_key));
        println!();

        let encrypted_data = common::read_exact(&mut file, data_size as usize)?;
        println!("Decrypting data...");
        decrypted_data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
    } else {
        println!("File is not encrypted.");
        decrypted_data = common::read_exact(&mut file, data_size as usize)?;
    }

    println!();

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        //file header
        let file_header = common::read_exact(&mut data_reader, 76)?;

        let file_name = common::string_from_bytes(&file_header[0..60]);

        let real_size = u32::from_le_bytes(file_header[60..64].try_into().unwrap());

        let stored_size = u32::from_le_bytes(file_header[64..68].try_into().unwrap());

        let _header_size = u32::from_le_bytes(file_header[68..72].try_into().unwrap());

        println!("- File: {}, Size: {}", file_name, real_size);

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

        println!("-- Saved file!");
    }

    println!();
    println!("Extraction finished!");
    
    Ok(())
}
use std::fs::{File};
use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::path::Path;
use std::io::{Cursor, Write};
use std::fs::{self, OpenOptions};

use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};
use binrw::{BinRead, BinReaderExt};

use crate::common;
use crate::keys;

#[derive(BinRead)]
struct Header {
    #[br(count = 8)] _magic_bytes: Vec<u8>,
    header_size: u32,
    data_size: u32,
	#[br(count = 4)] _crc32: Vec<u8>,
	mask: u32,
	_data_size_decompressed: u32,
	_padding2: u32,
	#[br(count = 512)] description_bytes: Vec<u8>,
}
impl Header {
    fn description(&self) -> String {
        common::string_from_bytes(&self.description_bytes)
    }
}

#[derive(BinRead)]
struct FileHeader {
    #[br(count = 60)] file_name_bytes: Vec<u8>,
    real_size: u32,
	stored_size: u32,
	_header_size: u32,
    _attributes: u32,
}
impl FileHeader {
    fn file_name(&self) -> String {
        common::string_from_bytes(&self.file_name_bytes)
    }
}

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
    ("Q5492", "q5492"),
    ("S5551", "q5551"), //Sharp
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
    let header: Header = file.read_le()?; 
    let signature = common::read_exact(&mut file, 128)?;
    let _ = common::read_exact(&mut file, 32)?; //unknown

    let version_bytes = common::read_exact(&mut file, header.header_size as usize - 704)?;
    let version = common::string_from_bytes(&version_bytes);

    println!("\nVersion: {}", version);
    println!("Description: \n{}", header.description());
    println!("Data size: {}", header.data_size);

    let decrypted_data;
    if (header.mask & 0x2000_0000) != 0 {
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

        let encrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
        println!("Decrypting data...");
        decrypted_data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
    } else {
        println!("File is not encrypted.");
        decrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    }

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        let file_header: FileHeader = data_reader.read_le()?; 

        println!("\nFile: {}, Size: {}", file_header.file_name(), file_header.real_size);

        let data = common::read_exact(&mut data_reader, file_header.stored_size as usize)?;

        let output_path = Path::new(&output_folder).join(file_header.file_name().trim_start_matches('/'));

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&data[..file_header.real_size as usize])?;

        println!("- Saved file!");
    }

    println!("\nExtraction finished!");
    
    Ok(())
}
use std::any::Any;
use crate::{ProgramContext, formats::Format};
pub fn format() -> Format {
    Format { name: "pfl_upg", detect_func: is_pfl_upg_file, run_func: extract_pfl_upg }
}

use rsa::{RsaPublicKey, BigUint};
use hex::decode;
use std::path::Path;
use std::io::{Read, Cursor, Write};
use std::fs::{self, OpenOptions};

use aes::Aes256;
use ecb::{Decryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
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
	header_size: u32,
    #[br(count = 4)] attributes: Vec<u8>,
}
impl FileHeader {
    fn file_name(&self) -> String {
        common::string_from_bytes(&self.file_name_bytes)
    }
}

pub fn is_pfl_upg_file(app_ctx: &ProgramContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let header = common::read_file(app_ctx.file, 0, 8)?;
    if header == b"2SWU3TXV" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
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

pub fn extract_pfl_upg(app_ctx: &ProgramContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file;
    let header: Header = file.read_le()?; 
    let signature = common::read_exact(&mut file, 128)?;
    let _ = common::read_exact(&mut file, 32)?; //unknown

    let version_bytes = common::read_exact(&mut file, header.header_size as usize - 704)?;
    let version = common::string_from_bytes(&version_bytes);

    println!("\nVersion: {}", version);
    println!("Description: \n{}", header.description());
    println!("Data size: {}", header.data_size);

    let mut decrypted_data;
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

        //for encrypted data we need to read file to end
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        println!("Decrypting data...");
        decrypted_data = decrypt_aes256_ecb(aes_key, &encrypted_data)?;
        decrypted_data.truncate(header.data_size as usize);
        
    } else {
        println!("File is not encrypted.");
        decrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    }

    let mut data_reader = Cursor::new(decrypted_data);

    while (data_reader.position() as usize) < data_reader.get_ref().len() {
        let file_header: FileHeader = data_reader.read_le()?; 

        //its a folder not a file
        if (file_header.attributes[3] & (1 << 1)) != 0 {
            println!("\nFolder - {}", file_header.file_name());
            let output_path = Path::new(app_ctx.output_dir).join(file_header.file_name().trim_start_matches('/'));
            fs::create_dir_all(output_path)?;
            continue
        }

        //extended name is used
        let file_name = if (file_header.attributes[2] & (1 << 7)) != 0 {
            let ex_name_size = file_header.header_size - 76; //76 is base file header size
            //println!("extended name {}, org name: {}", ex_name_size, file_header.file_name());
            let ex_name_bytes = common::read_exact(&mut data_reader, ex_name_size as usize)?;
            common::string_from_bytes(&ex_name_bytes)
        } else {
            file_header.file_name()
        };

        println!("\nFile - {}, Size: {}", file_name, file_header.real_size);
        let data = common::read_exact(&mut data_reader, file_header.stored_size as usize)?;

        let output_path = Path::new(app_ctx.output_dir).join(file_name.trim_start_matches('/'));
        let output_path_parent = output_path.parent().expect("Failed to get parent of the output path!");

        //prevent collisions
        if output_path_parent.exists() && output_path_parent.is_file() {
            println!("[!] Warning: File collision detected, Skipping this file!");
            continue
        }

        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::create_dir_all(app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&data[..file_header.real_size as usize])?;

        //if it contains a PFL upg in itself to extract
        //if (file_header.attributes[3] & (1 << 2)) != 0 {
        //   println!("Container file");
        //}

        println!("- Saved file!");
    }

    println!("\nExtraction finished!");
    
    Ok(())
}
use std::fs;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Write};
use hex::decode;
use sha1::{Digest, Sha1};

use crate::utils::common;
use crate::keys;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};

use md5;

pub fn is_samsung_old_dir(path: &PathBuf) -> bool {
    if Path::new(&path).join("image").is_dir() & Path::new(&path).join("image/info.txt").exists(){
        true
    } else {
        false
    }
}

fn decrypt_xor(data: &[u8], key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}

pub fn extract_samsung_old(path: &PathBuf, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {

    let fw_info = fs::read_to_string(Path::new(&path).join("image/info.txt"))?;
    println!("Firmware info: {}", fw_info);

    let image_path = Path::new(&path).join("image");

    let mut secret: Option<&str> = None;

    //find secret
    for (prefix, value) in keys::SAMSUNG {
        if fw_info.starts_with(prefix) {
            secret = Some(value);
            break;
        }
    }
    if let Some(p) = secret {
        println!("Secret: {}", p);
    } else {
        println!("Sorry, this firmware is not supported!");
        std::process::exit(1);
    }
    
    for entry in fs::read_dir(image_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "sec" {
                    let file = File::open(&path)?;
                    let filename = path.file_name().unwrap().to_str().unwrap();
                    let file_size = file.metadata()?.len();
                    println!("\nFile - {}", filename);

                    let data = common::read_file(&file, 0, file_size.try_into().unwrap())?;
                    let salt = &data[8..16];

                    let key_md5;
                    let iv_md5;

                    //Old -> key: md5 of (sha1 of secret as TEXT + salt)
                    //       iv: md5 of (md5 of key + key)

                    //2012 -> key: md5 of (secret(as bytes) + salt)
                    //        iv: md5 of (md5 of key + key)

                    if fw_info.starts_with("T-ECP") {
                        let mut key = Vec::new();
                        key.extend_from_slice(&decode(secret.unwrap())?);
                        key.extend_from_slice(salt);
                        key_md5 = md5::compute(&key);

                        let mut iv = Vec::new();
                        iv.extend_from_slice(&key_md5.0);
                        iv.extend_from_slice(&key);
                        iv_md5 = md5::compute(&iv);

                    } else {
                        let mut hasher = Sha1::new();
                        hasher.update(secret.as_ref().unwrap());
                        let secret_digest = hasher.finalize();
                        // yes it needs to be a string first then into bytes
                        let secret_digest_string = format!("{:x}", secret_digest);
                        let secret_digest_bytes = secret_digest_string.as_bytes();

                        let mut key = Vec::new();
                        key.extend_from_slice(&secret_digest_bytes);
                        key.extend_from_slice(salt);
                        key_md5 = md5::compute(&key);

                        let mut iv = Vec::new();
                        iv.extend_from_slice(&key_md5.0);
                        iv.extend_from_slice(&key);
                        iv_md5 = md5::compute(&iv);
                    }     

                    //println!("Key: {:02x?}", key_md5);
                    //println!("IV: {:02x?}", iv_md5);
                    let end = file_size - 260;
                    println!("- Decrypting file...");
                    let decrypted_data = decrypt_aes128_cbc_pcks7(&data[16..end.try_into().unwrap()], &key_md5, &iv_md5)?;

                    println!("-- DeXORing file...");
                    let xor_key = fw_info.split_whitespace().next().unwrap();
                    let out_data = decrypt_xor(&decrypted_data, xor_key);
                    
                    let output_path = Path::new(&output_folder).join(filename.rsplit_once('.').map(|(left, _)| left).unwrap());

                    fs::create_dir_all(&output_folder)?;
                    let mut out_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(output_path)?;

                    out_file.write_all(&out_data)?;

                    println!("--- Saved file!");
                }
            }
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
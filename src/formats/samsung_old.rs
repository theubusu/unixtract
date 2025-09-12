use std::fs;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{Write};
use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};
use sha1::{Digest, Sha1};

type Aes128CbcDec = Decryptor<Aes128>;

use crate::common;

use md5;

pub fn is_samsung_old_dir(path: &PathBuf) -> bool {
    if Path::new(&path).join("image").is_dir() & Path::new(&path).join("image/info.txt").exists(){
        true
    } else {
        false
    }
}

fn decrypt_aes(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
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
    let mut secret = "";
    let secret_t_ecp = [0x3E, 0xF6, 0x06, 0x72, 0x62, 0xCF, 0x0C, 0x67, 0x85, 0x98, 0xBF, 0xF2, 0x21, 0x69, 0xD1, 0xF1, 0xEA, 0x57, 0xC2, 0x84];

    // from samygo tool
    if fw_info.starts_with("T-GA"){
        secret = "SHWJUH:85a045ae-2296-484c-b457-ede832fcfbe1-646390a3-105e-40aa-85f6-da3086c70111";
    } else if fw_info.starts_with("T-MST5"){
        secret = "SHWJUH:eceb2c14-db11-425e-9ebf-5f9607f0eb4b-3c38193e-751e-4719-8884-9e76322c0cec";
    } else if fw_info.starts_with("B-FIRHT7"){
        secret = "d6442d-7b46b2f4-0f11-4623-af63-8bb0a0d54c80-a22fbe2c-1bb5-49cc-b194-25c0f2b870f4";
    } else if fw_info.starts_with("B-FIRU") | fw_info.starts_with("B-FIRH") | fw_info.starts_with("B-FIRBSP") | fw_info.starts_with("B-FIR2"){
        secret = "SHWJUH:db48ad51-c784-4f06-af57-1070a910c536-6a028bb5-e83e-45da-b326-a3a39ccba26c";
    } else if fw_info.starts_with("B-FIRB"){
        secret = "d6442d-7b46b2f4-0f11-4623-af63-8bb0a0d54c80-a22fbe2c-1bb5-49cc-b194-25c0f2b870f4";
    } else if fw_info.starts_with("T-MST10P"){
        secret = "b4c136-fbc93576-b3e8-4035-bf4e-ba4cb4ada1ac-f0d81cc4-8301-4832-bd60-f331295743ba";
    } else if fw_info.starts_with("B-ECB"){
        secret = "SHWJUH:8fb684a9-84c1-46cf-aa81-977bce241542-6db4c136-8540-4ee4-8704-d9cd18590d11";
    } else if fw_info.starts_with("T-VAL"){
        secret = "A435HX:d3e90afc-0f09-4054-9bac-350cc8dfc901-7cee72ea-15ae-45ce-b0f5-00001abc2010";
    } else if fw_info.starts_with("T-TDT"){
        secret = "A435HX:d3e90afc-0f09-4054-9bac-350cc8dfc901-7cee72ea-15ae-45ce-b0f5-00002abc2010";
    } else if fw_info.starts_with("T-MSX"){
        secret = "A435HX:d3e90afc-0f09-4054-9bac-350cc8dfc901-7cee72ea-15ae-45ce-b0f5-00004abc2010";
    } else if fw_info.starts_with("T-CH"){
        secret = "A435HX:d3e90afc-0f09-4054-9bac-350cc8dfc901-7cee72ea-15ae-45ce-b0f5-611c4f8d4a71";
    } else if fw_info.starts_with("T-ECP") {
    } else {
        println!("Sorry, this firmware is not supported!");
        return Ok(());
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
                    println!("File: {}", filename);
                    let data = common::read_file(&file, 0, file_size.try_into().unwrap())?;
                    let salt = &data[8..16];

                    let key_md5;
                    let iv_md5;

                    //Old -> key: md5 of (sha1 of secret as TEXT + salt)
                    //       iv: md5 of (md5 of key + key)

                    //2012 -> key: md5 of (secret + salt)
                    //        iv: md5 of (md5 of key + key)
                    if fw_info.starts_with("T-ECP") {
                        let key: Vec<u8> = [&secret_t_ecp, salt].concat();
                        key_md5 = md5::compute(&key);

                        let mut iv = Vec::new();
                        iv.extend_from_slice(&key_md5.0);
                        iv.extend_from_slice(&key);
                        iv_md5 = md5::compute(&iv);
                    } else {
                        let mut hasher = Sha1::new();
                        hasher.update(secret);
                        let secret_digest = hasher.finalize();
                        // yes it needs to be a string first then into bytes
                        let secret_digest_string = format!("{:x}", secret_digest);
                        let secret_digest_bytes = secret_digest_string.as_bytes();

                        let key: Vec<u8> = [&secret_digest_bytes, salt].concat();
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
                    let decrypted_data = decrypt_aes(&data[16..end.try_into().unwrap()], &key_md5, &iv_md5)?;

                    println!("- DeXORing file...");
                    let xor_key = fw_info.split_whitespace().next().unwrap();
                    let out_data = decrypt_xor(&decrypted_data, xor_key);
                    
                    let output_path = Path::new(&output_folder).join(filename.rsplit_once('.').map(|(left, _)| left).unwrap());

                    fs::create_dir_all(&output_folder)?;
                    let mut out_file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(output_path)?;

                    out_file.write_all(&out_data)?;
                }
            }
        }
    }


    Ok(())
}
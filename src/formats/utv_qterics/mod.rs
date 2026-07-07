use std::any::Any;
use crate::AppContext;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::Write;
use binrw::BinReaderExt;

use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

use rsa::{RsaPrivateKey, Oaep};
use rsa::pkcs8::DecodePrivateKey;
use sha1::Sha1;
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm, Nonce};

use crate::utils::common;

pub fn is_utv_qterics_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header_b64 = common::read_file(&file, 4, 20)?;
    if header_b64 == b"eyJhbGciOiJSUzUxMiJ9" {      //base64 encoded {"alg":"RS512"}, which is what the header needs to be
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_utv_qterics(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let metadata_size: u32 = file.read_be()?;
    let metadata = common::read_exact(&mut file, metadata_size as usize)?;

    //metadata has 3 base64(URL with no padding) encoded parts(header, claims, signature), split by dot
    let meta_parts: Vec<&[u8]> = metadata.split(|&b| b == b'.').collect();
    if meta_parts.len() != 3 {
        return Err("invalid metadata parts count".into());
    }

    let claims_dec = general_purpose::URL_SAFE_NO_PAD.decode(meta_parts[1])?;
    opt_dump_dec_hdr(app_ctx, &claims_dec, "claims")?;
    
    let claims: Value = serde_json::from_slice(&claims_dec)?;

    let filename = claims["upf"].as_str().ok_or("claims is missing upf")?;
    let version = claims["upn"].as_str().ok_or("claims is missing upn")?;
    let file_size = claims["siz"].as_u64().ok_or("claims is missing siz")?;
    let block_size = claims["blk"].as_u64().ok_or("claims is missing blk")?;
    
    println!("\nFile info -\nFilename: {}\nVersion: {}\nFile size: {}\nBlock size: {}", filename, version, file_size, block_size);

    //key(s) encrypted with private key
    let key = claims["key"].as_str().ok_or("claims is missing key")?;
    let enc_key = general_purpose::STANDARD.decode(&key)?;

    //find private key that decrypts the encrypted key
    let mut dec_key: Option<Vec<u8>> = None;
    for (name, keys) in app_ctx.keys.get_collection("UTV_QTERICS")? {
        let key_str= common::string_from_bytes(&general_purpose::STANDARD.decode(keys.first().unwrap())?);
        let private_key = RsaPrivateKey::from_pkcs8_pem(&key_str)?;
        if let Ok(dec) = private_key.decrypt(Oaep::new::<Sha1>(), &enc_key) {
            if dec.len() == 44 {
                println!("\nUsing key: {}\n", name);
                dec_key = Some(dec);
                break
            }
        }
    }
    let dec_key = if let Some(_dec_key) = dec_key {
        _dec_key
    } else {
        return Err("No matching key found!".into());
    };

    let aes_key = &dec_key[0..16];
    let aes_aad = &dec_key[16..32];
    let nonce_base   = &dec_key[32..44];

    let cipher = Aes128Gcm::new(aes_key.try_into().unwrap());

    fs::create_dir_all(&app_ctx.output_dir)?;
    let output_path = Path::new(&app_ctx.output_dir).join(filename);
    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

    let block_count = (file_size + block_size - 1) / block_size;
    for i in 0..block_count {
        //handle last block
        let size = if i == block_count-1 && (file_size % block_size) < block_size {
            file_size % block_size
        } else {
            block_size
        };
        println!("- Decrypting block {}/{} (size: {})...", i+1, block_count, size);

        //16 byte aes GCM tag follows block
        let block_and_tag = common::read_exact(&mut file, size as usize + 16)?;

        //first 4 bytes of nonce is replaced by the block idx in u32 BE
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&u32::to_be_bytes(i as u32));
        nonce_bytes[4..12].copy_from_slice(&nonce_base[4..12]);

        let nonce = Nonce::try_from(&nonce_bytes[..])?;
        let decrypted = cipher.decrypt(&nonce, Payload { msg: &block_and_tag, aad: aes_aad })?;
        out_file.write_all(&decrypted)?;
    }

    Ok(())
}
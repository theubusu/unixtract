mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_ecb, decrypt_aes256_cbc_nopad};
use crate::utils::global::opt_dump_dec_hdr;
use include::*;

pub fn is_fdat_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let dat_magic = common::read_file(&file, 0, 8)?;
    if dat_magic == b"\x89\x55\x46\x55\x0D\x0A\x1A\x0A" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_fdat(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    //skip dat magic
    file.seek(SeekFrom::Start(8))?;

    //find fdat chunk
    let mut fdat_size: Option<u32> = None;
    let file_size = file.metadata()?.len();
    while file.stream_position()? < file_size {
        let chunk_size: u32 = file.read_be()?;
        let chunk_name = common::read_exact(&mut file, 4)?;
        if chunk_name == b"FDAT" {
            fdat_size = Some(chunk_size);
            break
        } else {
            file.seek(SeekFrom::Current(chunk_size as i64))?;
        }
    }
    let fdat_size = if let Some(_fdat_size) = fdat_size{
        println!("FDAT size: {}", _fdat_size);
        _fdat_size
    } else {
        return Err("FDAT chunk not found".into());
    };
    let fdat_offset = file.stream_position()?;

    //find encryption
    let mut encryption_mode: Option<EncryptionMode> = None;

    //keep first decrypted block to make life easier
    let mut first_block_decrypted: Vec<u8> = vec![];
    
    //1st gen (custom sha derived cipher)
    let first_block_encrypted = common::read_exact(&mut file, 1000 /* sha block size is 1000 */)?;
    for (name, keys) in app_ctx.keys.get_collection("FDAT_SHA_KEYS")? {
        let key_bytes = keys.first().unwrap().as_slice();
        let mut crypter = ShaCrypter::new(key_bytes.try_into().unwrap());
        let decrypted = crypter.decrypt_block(&first_block_encrypted);
        //block starts with checksum, check to see if decryption was correct
        if u16::from_le_bytes([decrypted[0], decrypted[1]]) == calc_sum(&decrypted[2..]) {
            println!("- 1st gen firmware ({}) detected!", name);
            encryption_mode = Some(EncryptionMode::Sha(crypter));
            first_block_decrypted = decrypted[4..].to_vec();
            break
        }
    }

    //try aes types
    if encryption_mode.is_none() {
        file.seek(SeekFrom::Start(fdat_offset))?;
        let common_aes_key = app_ctx.keys.get_key_as_arr::<16>("FDAT_COMMON_AES_KEY", 0)?;
        let first_block_encrypted = common::read_exact(&mut file, 1024 /* aes block size is 1024 */)?;
        let mut cmn_decrypted = decrypt_aes128_ecb(&common_aes_key, &first_block_encrypted)?;
        let expected_checksum = u16::from_le_bytes([cmn_decrypted[0], cmn_decrypted[1]]);
   
        if expected_checksum == calc_sum(&cmn_decrypted[2..]) {
            //2nd gen (1 pass aes128ecb)
            println!("- 2nd gen firmware (CXD4132) detected!");
            encryption_mode = Some(EncryptionMode::AesEcb(common_aes_key));
            first_block_decrypted = cmn_decrypted[4..].to_vec();
        } else {
            //3rd gen (2 passes of aes128ecb, but first 512 bytes of 1st block use only the first pass' key)
            let cxd90014_aes_key = app_ctx.keys.get_key_as_arr::<16>("FDAT_CXD90014_AES_KEY", 0)?;
            let decrypted_2nd_part = decrypt_aes128_ecb(&cxd90014_aes_key, &cmn_decrypted[512..])?;
            cmn_decrypted[512..].copy_from_slice(&decrypted_2nd_part);
            if expected_checksum == calc_sum(&cmn_decrypted[2..]) {
                println!("- 3rd gen firmware (CXD90014) detected!");
                encryption_mode = Some(EncryptionMode::DoubleAesEcb((common_aes_key, cxd90014_aes_key)));
                first_block_decrypted = cmn_decrypted[4..].to_vec();
            } else {
                //4rd gen (aes256cbc, but first 512 bytes of 1st block use the common aes128ecb key)
                //iv is at -0x110 from FDAT end
                let cxd90045_aes_key = app_ctx.keys.get_key_as_arr::<32>("FDAT_CXD90045_AES_KEY", 0)?;
                let iv: [u8; 16] = common::read_file(&mut file, (fdat_offset + fdat_size as u64) - 0x110, 16)?.try_into().unwrap();
                file.seek(SeekFrom::Start(fdat_offset + 1024))?;
                let decrypted_2nd_part = decrypt_aes256_cbc_nopad(&first_block_encrypted[512..], &cxd90045_aes_key, &iv)?;
                cmn_decrypted[512..].copy_from_slice(&decrypted_2nd_part);
                if expected_checksum == calc_sum(&cmn_decrypted[2..]) {
                    println!("- 4th gen firmware (CXD90045) detected!");
                    //UPDATE iv, the CBC state is kept between blocks. 
                    let new_iv: [u8; 16] = first_block_encrypted[1008..1024].try_into().unwrap();
                    encryption_mode = Some(EncryptionMode::AesCbc((cxd90045_aes_key, new_iv)));
                    first_block_decrypted = cmn_decrypted[4..].to_vec();
                }
            }
        }
    }

    let mut encryption_mode = if let Some(_encryption_mode) = encryption_mode{
        _encryption_mode
    } else {
        return Err("Cannot decrypt data".into());
    };

    opt_dump_dec_hdr(&app_ctx, &first_block_decrypted[..512], "header")?;

    //now decrypt all FDAT data
    let mut decrypted_data: Vec<u8> = vec![];

    //append saved first block
    decrypted_data.extend_from_slice(&first_block_decrypted);

    println!("\nDecrypting data...");
    loop {
        let block_size: usize = match encryption_mode {
            EncryptionMode::Sha(_) => 1000,
            _ => 1024,
        };
        let encrypted_block = common::read_exact(&mut file, block_size)?;
        let decrypted_block = match &mut encryption_mode {
            EncryptionMode::Sha(crypter) => crypter.decrypt_block(&encrypted_block),
            EncryptionMode::AesEcb(key) => decrypt_aes128_ecb(&key, &encrypted_block)?,
            EncryptionMode::DoubleAesEcb((key1, key2)) => {
                let decrypted1 = decrypt_aes128_ecb(&key1, &encrypted_block)?;
                decrypt_aes128_ecb(&key2, &decrypted1)?
            },
            EncryptionMode::AesCbc((key, iv)) => {
                let decrypted = decrypt_aes256_cbc_nopad(&encrypted_block, &key, &iv)?;
                //UPDATE iv, the CBC state is kept between blocks. 
                *iv = encrypted_block[1008..1024].try_into().unwrap();
                decrypted
            }
        };

        //block starts with metadata
        let (_block_checksum, block_size_is_last) = (
            u16::from_le_bytes([decrypted_block[0], decrypted_block[1]]), u16::from_le_bytes([decrypted_block[2], decrypted_block[3]])
        );
        let block_size = (block_size_is_last & 0x7fff) as usize;
        let block_is_last: bool = (block_size_is_last & 0x8000) != 0;
        
        let block_data = &decrypted_block[4..4+block_size];
        decrypted_data.extend_from_slice(&block_data);
        
        if block_is_last {
            break
        }
    }

    let mut data_reader = Cursor::new(decrypted_data);
    let header: FdatHeader = data_reader.read_le()?;

    println!("\nFile info -\nMode: {}\nVersion: {}.{}\nModel: 0x{:x}\nRegion: 0x{:x}\nFirmware size: {}\nFilesystem count: {}",
            header.mode_type as char, header.version_major, header.version_minor, header.model, header.region, header.firmware_size, header.num_filesystems);

    fs::create_dir_all(&app_ctx.output_dir)?;

    //extract filesystems
    for (i, fs_entry) in header.filesystem_entries.iter().enumerate() {
        println!("\nFilesystem #{} - Mode: {}, Offset: {}, Size: {}", i+1, fs_entry.mode_type as char, fs_entry.offset, fs_entry.size);
        if fs_entry.size == 0 {
            println!("- Skipping empty filesystem...");
            continue;
        }

        data_reader.seek(SeekFrom::Start(fs_entry.offset.into()))?;
        let data = common::read_exact(&mut data_reader, fs_entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("fs_{}.bin", i+1));
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    //extract main firmware
    println!("\nFirmware - Offset: {}, Size: {}", header.firmware_offset, header.firmware_size);
    data_reader.seek(SeekFrom::Start(header.firmware_offset.into()))?;
    let data = common::read_exact(&mut data_reader, header.firmware_size as usize)?;

    let output_path = Path::new(&app_ctx.output_dir).join("firmware.tar");
    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
    out_file.write_all(&data)?;

    println!("- Saved file!");

    Ok(())
}
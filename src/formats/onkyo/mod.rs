mod include;
mod crypto;
use std::any::Any;
use crate::{AppContext, InputTarget};
use crate::utils::aes::decrypt_aes256_cbc_nopad;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;
use crypto::*;

struct OnkyoCtx {
    header_size: u32,
    encryption: EncryptionMode,
}

pub fn is_onkyo_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let enc_inihdr = common::read_file(&file, 0, 32)?;
    let hdr_key = app_ctx.keys.get_key_as_arr::<8>("ONKYO_HEADER_KEY", 0)?;
    let mut dec_inihdr= ub_encrypte_block(&enc_inihdr, &hdr_key);

    if dec_inihdr.starts_with(ONKYO_MAGIC) {
        let header_size = u32::from_le_bytes(dec_inihdr[16..20].try_into().unwrap());
        return Ok(Some(Box::new(OnkyoCtx {header_size, encryption: EncryptionMode::Old})));
    }

    //new enc
    let network: [u8; 8] = app_ctx.keys.get_key_as_arr::<8>("ONKYO_NEW_NETWORK_KEY", 0)?;
    dec_inihdr = crypt_new(&enc_inihdr, &network);
    if dec_inihdr.starts_with(&NEW_MAGIC_ID) {
        let header_size = u32::from_le_bytes(dec_inihdr[16..20].try_into().unwrap());
        return Ok(Some(Box::new(OnkyoCtx {header_size, encryption: EncryptionMode::New})));
    }

    //new enc + AES wrap
    for (_name, keys) in app_ctx.keys.get_collection("ONKYO_NEW_KEYS")? {
        let seed: [u8; 32] = keys.first().unwrap().as_slice().try_into().unwrap();       
        let (key, iv) = derive_aes_key(&seed);

        //decrypt AES with keys from seed
        dec_inihdr = decrypt_aes256_cbc_nopad(&enc_inihdr, &key, &iv)?;
        
        //decrypt custom with Network key
        dec_inihdr = crypt_new(&dec_inihdr, &network);

        if dec_inihdr.starts_with(&NEW_MAGIC_ID) {
            let header_size = u32::from_le_bytes(dec_inihdr[16..20].try_into().unwrap());
            return Ok(Some(Box::new(OnkyoCtx {header_size, encryption: EncryptionMode::NewAES((key, iv))})));
        }
    }

    Ok(None)
}

pub fn extract_onkyo(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<OnkyoCtx>().expect("Missing context");

    println!("Header size: {}", ctx.header_size);

    let hdr_key = app_ctx.keys.get_key_as_arr::<8>("ONKYO_HEADER_KEY", 0)?;
    let network_key: [u8; 8] = app_ctx.keys.get_key_as_arr::<8>("ONKYO_NEW_NETWORK_KEY", 0)?;
    let new_data_key: [u8; 8] = app_ctx.keys.get_key_as_arr::<8>("ONKYO_NEW_DATA_KEY", 0)?;

    //need to read entire file and optionally aes decrypt it
    let mut file_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_data)?;

    if let EncryptionMode::NewAES((key, iv)) = &ctx.encryption {
        println!("- Decrypting file...");
        file_data = decrypt_aes256_cbc_nopad(&file_data, key, iv)?;
    }
    let mut data_rdr = Cursor::new(file_data);

    let enc_hdr = common::read_exact(&mut data_rdr, ctx.header_size as usize)?;
    let dec_hdr = match ctx.encryption {
        EncryptionMode::Old => ub_encrypte_block(&enc_hdr, &hdr_key),
        EncryptionMode::New => crypt_new(&enc_hdr, &network_key),
        EncryptionMode::NewAES((_, _)) => crypt_new(&enc_hdr, &network_key),
    };

    opt_dump_dec_hdr(app_ctx, &dec_hdr, "header")?;
    let mut hdr_rdr = Cursor::new(dec_hdr);

    let hdr: Header = hdr_rdr.read_le()?;

    //read info section
    hdr_rdr.seek(SeekFrom::Start(hdr.pack_info_offset as u64))?;
    let info: PackInfo = hdr_rdr.read_le()?;
    println!("Info -\nPackage ID: {}\nVersion: {}\nEntry count: {}\nEntries in file: {}\nPack: {}/{}",
            info.package_id(), info.package_version(), info.entry_count, info.entries_in_file, info.pack_id, info.pack_count,);

    if info.entries_in_file == 0 {
        return Err("There is nothing to extract in this pack".into())   //should this be an error?
    }

    //..."IDsVersions" section
    hdr_rdr.seek(SeekFrom::Start(hdr.ids_versions_offset as u64))?;
    let mut entries: Vec<IDsVersionsEntry> = Vec::new();
    for _ in 0..info.entry_count {
        let entry: IDsVersionsEntry = hdr_rdr.read_le()?;
        entries.push(entry);
    }

    //...table section
    hdr_rdr.seek(SeekFrom::Start(hdr.table_offset as u64))?;
    let mut data_entries: Vec<TableEntry> = Vec::new();
    for _ in 0..info.entry_count {
        let entry: TableEntry = hdr_rdr.read_le()?;
        data_entries.push(entry);
    }

    //
    let mut act_ei = 0;
    for (i, entry) in entries.iter().enumerate() {
        let data_entry = &data_entries[i];

        if entry.pack_location == 0 || (data_entry.offset == 0 && data_entry.checksum == 0){
            continue;
        }

        act_ei += 1;
        println!("\n({}/{}) - {}, Size: {}, Offset: {}, Pack location: {}",
                act_ei, info.entries_in_file, entry.id(), data_entry.size, data_entry.offset, entry.pack_location);

        data_rdr.seek(SeekFrom::Start(data_entry.offset as u64))?;
        let data = common::read_exact(&mut data_rdr, data_entry.size as usize)?;

        let mut out_data;

        // -- try to decrypt --
        let mut dec_key: Option<[u8; 8]> = None;
        let mut is_new = false;
        let mut is_pack = false;

        //try new network and component data keys
        for new_key in [network_key, new_data_key] {
            let dec_new = crypt_new(&data[..32], &new_key);
            if dec_new.starts_with(NEW_MAGIC_ID){
                is_new = true;

                //naive pack detection for new
                let header_size = u32::from_le_bytes(dec_new[16..20].try_into().unwrap());
                if header_size < data.len() as u32 && header_size < 4096 && header_size > 32 {
                    let dec_hdr = crypt_new(&data[..header_size as usize], &new_key);
                    let calc = checksum(&dec_hdr[24..]);
                    let exp = u32::from_le_bytes(dec_hdr[20..24].try_into().unwrap());
                    //println!("calc={}, exp={}", calc, exp);

                    is_pack = (calc==exp) as bool ;
                }
                if !is_pack {
                    dec_key = Some(new_key);
                }
                break;
            }
        }

        if dec_key.is_none() && !is_pack {
            //try using standard data key
            let data_key = app_ctx.keys.get_key_as_arr::<8>("ONKYO_DATA_KEY", 0)?;
            if ub_encrypte_block(&data[..16], &data_key).starts_with(ONKYO_MAGIC) {
                dec_key = Some(data_key);

            //try header key, if success it means this is a package inside a package, and it should not be decrypted
            } else if ub_encrypte_block(&data[..16], &hdr_key).starts_with(ONKYO_MAGIC) {
                is_pack = true;

            //if not matched with data key, try to calc key
            } else {
                let calced_key = calc_key(&data[..8]);

                if ub_encrypte_block(&data[..16], &calced_key).starts_with(ONKYO_MAGIC) {
                    dec_key = Some(calced_key);
                }
            }
        }

        if let Some(key) = dec_key {
            println!("- Detected encrypted data, decrypting...");
            out_data = if is_new {
                crypt_new(&data, &key)
            } else {
                ub_encrypte_block(&data, &key)
            };
            out_data.drain(0..16);      //remove ONKYO Encryption heading

        } else if is_pack {
            out_data = data;

        } else {
            println!("- Failed to decrypt data or entry is not encrypted, saving raw data...");
            out_data = data;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", act_ei, entry.id()));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;        
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");

        //extract an inner pack
        if is_pack {
            let r_out_file = File::open(&output_path)?;
            let in_ctx: AppContext = AppContext { 
                input: InputTarget::File(r_out_file), 
                output_dir: app_ctx.output_dir.join(format!("_{}_{}.bin", act_ei, entry.id())), 
                options: app_ctx.options,
                keys: app_ctx.keys,
            };

            //do check and extarct
            if let Some(result) = is_onkyo_file(&in_ctx)? {
                println!("- Extracting inner pack...");
                extract_onkyo(&in_ctx, result)?;
            };
        }

    }

    Ok(())
}

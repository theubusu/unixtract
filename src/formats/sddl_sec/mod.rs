//base: sddl_dec 7.0 https://github.com/theubusu/sddl_dec
pub mod include;
mod util;
use std::any::Any;
use crate::AppContext;

use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::common::{string_from_bytes, read_exact};
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes128_cbc_pcks7};
use crate::utils::compression::{decompress_zlib};
use include::*;
use util::split_peaks_file;

pub fn is_sddl_sec_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 32).expect("Failed to read from file.");
    let deciph_header = decipher(&header);
    if deciph_header.starts_with(b"\x11\x22\x33\x44") {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

fn get_sec_file(mut file: &File, key_entry: &KeyEntry) -> Result<(FileHeader, Vec<u8>), Box<dyn std::error::Error>> {
    //new type check because only new is Pcks7.. i know
    let new_type = match key_entry {
        KeyEntry::AESPcks7(_) => true,
        _ => false
    };

    let dec_header = KeyEntry::decrypt(key_entry, &read_exact(&mut file, 32)?)?;
    let mut hdr_reader = Cursor::new(dec_header);
    let file_header: FileHeader = hdr_reader.read_be()?;

    let enc_size= if new_type {
        file_header.size() as usize
    } else {
        //extra ciphered data before encrypted data, prefixed by size, like "0021XXXXXX PEAKS.T00/12900002"
        //this counts into file size but not decrypt size
        let extra_size: usize = string_from_bytes(&read_exact(&mut file, 4)?).parse().unwrap();
        let _extra_data = read_exact(&mut file, extra_size)?;

        file_header.size() as usize - (extra_size + 4)
    };

    let dec_data = KeyEntry::decrypt(key_entry, &read_exact(&mut file, enc_size)?)?;
    let file_data = if new_type {
        dec_data
    } else {
        let mut data_rdr = Cursor::new(dec_data);

        //extra info in enc data, like "0021XXXXXX PEAKS.T00/12900002000000571800"
        //part before size looks to be a duplicate of previous extra data, probably for signing purpose, size used for unpad
        let extra_size: usize = string_from_bytes(&read_exact(&mut data_rdr, 4)?).parse().unwrap();
        let _extra_data = read_exact(&mut data_rdr, extra_size + 4)?;

        let data_size: usize = string_from_bytes(&read_exact(&mut data_rdr, 12)?).parse().unwrap();
        read_exact(&mut data_rdr, data_size)?
    };

    Ok((file_header, file_data))
}

fn parse_tdi_to_modules(tdi_data: Vec<u8>) -> Result<Vec<TdiTgtInf>, Box<dyn std::error::Error>> {
    let mut tdi_reader = Cursor::new(tdi_data);
    let tdi_header: TdiHead = tdi_reader.read_be()?;
    if tdi_header.download_id != DOWNLOAD_ID {
        return Err("Invalid TDI header!".into());
    }
    if tdi_header.format_version != SUPPORTED_TDI_VERSION {
        return Err(format!("Unsupported TDI format version {}! (The supported version is {})", tdi_header.format_version, SUPPORTED_TDI_VERSION).into());
    }

    println!("[TDI] Group count: {}", tdi_header.num_of_group);
    let mut modules: Vec<TdiTgtInf> = Vec::new();

    for _i in 0..tdi_header.num_of_group {
        let group_head: TdiGroupHead = tdi_reader.read_be()?;
        println!("[TDI] Group ID: {}, Target count: {}", group_head.group_id, group_head.num_of_target);

        for _i in 0..group_head.num_of_target {
            let tgt_inf: TdiTgtInf = tdi_reader.read_be()?;
            println!("[TDI] - {}, Target ID: {}, Segment count: {}, Version: {}",
                    tgt_inf.module_name(), tgt_inf.target_id, tgt_inf.num_of_txx, tgt_inf.version_string());

            //push unique modules
            if !modules.iter().any(|m| m.module_name() == tgt_inf.module_name()) {
                modules.push(tgt_inf);
            }
        }
    }

    Ok(modules)
}

pub fn extract_sddl_sec(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let save_extra = app_ctx.has_option("sddl_sec:save_extra");

    let mut secfile_hdr_reader = Cursor::new(decipher(&read_exact(&mut file, 32)?));
    let secfile_header: SecHeader = secfile_hdr_reader.read_be()?;

    println!("File info -\nKey ID: {}\nGroup count: {}\nModule file count: {}", secfile_header.key_id(), secfile_header.grp_num(), secfile_header.prg_num());

    //by knowing that the first file is always SDIT.FDI, find key(and mode)
    let try_hdr = read_exact(&mut file, 0x20)?;

    let mut key: Option<KeyEntry> = None;

    //for new, key will always be the same
    if let Ok(dec) = decrypt_aes128_cbc_pcks7(&try_hdr, &NEW_KEY.key, &NEW_KEY.iv) {
        if dec.starts_with(TDI_FILENAME.as_bytes()) {
            println!("- New type detected\n");
            key = Some(KeyEntry::AESPcks7(NEW_KEY));
        }
    }
    //new did not match, try all old AES keys
    if key.is_none() {
        for key_entry in OLD_KEYS_AES {
            let dec = decrypt_aes128_cbc_nopad(&try_hdr, &key_entry.key, &key_entry.iv)?;
            if dec.starts_with(TDI_FILENAME.as_bytes()) {
                println!("- Old type detected with AES key={}, iv={}\n", hex::encode(key_entry.key) ,hex::encode(key_entry.iv));
                key = Some(KeyEntry::AES(key_entry));
                break
            }
        }        
    }
    //...old DES keys
    if key.is_none() {
        for key_entry in OLD_KEYS_DES {
            let dec = decrypt_3des(&try_hdr, &key_entry)?;
            if dec.starts_with(TDI_FILENAME.as_bytes()) {
                println!("- Old type detected with DES key={}, iv={}\n", hex::encode(key_entry.key) ,hex::encode(key_entry.iv));
                key = Some(KeyEntry::DES(key_entry));
                break
            }
        }        
    }
    //nothing matched, quit
    if key.is_none() {
        return Err("No matching key found!".into());
    }

    // -- key search end

    let key = key.unwrap();
    fs::create_dir_all(&app_ctx.output_dir)?;
    file.seek(SeekFrom::Start(0x20))?;

    let (tdi_file, tdi_data) = get_sec_file(&file, &key)?;
    println!("[TDI] Name: {}, Size: {}", tdi_file.name(), tdi_file.size());
    if save_extra { //Save SDIT
        let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&app_ctx.output_dir).join(tdi_file.name()))?;
        out_file.write_all(&tdi_data)?;
    }
    if tdi_file.name() != TDI_FILENAME {
        return Err(format!("Invalid TDI filename {}!, expected: {}", tdi_file.name(), TDI_FILENAME).into());
    }
    //parse TDI
    let modules = parse_tdi_to_modules(tdi_data)?;

    //get info files, each info file belongs to its respecitve group in the TDI
    for i in 0..secfile_header.grp_num() {
        let (info_file, info_data) = get_sec_file(&file, &key)?;
        println!("\n[INFO] ID: {}, Name: {}, Size: {}", i, info_file.name(), info_file.size());
        if !info_file.name().ends_with(INFO_FILE_EXTENSION) {
            return Err(format!("Info file {} does not have the expected extension {}!", info_file.name(), INFO_FILE_EXTENSION).into());
        }
        if save_extra { //Save info file
            let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&app_ctx.output_dir).join(info_file.name()))?;
            out_file.write_all(&info_data)?;
        }
        //print info file
        println!("{}", String::from_utf8_lossy(&info_data));
    }

    //parse module data
    for (i, module) in modules.iter().enumerate(){
        println!("\nModule #{}/{} - {}, Target ID: {}, Segment count: {}, Version: {}", 
                i+1, &modules.len(), module.module_name(), module.target_id, module.num_of_txx, module.version_string());

        let mut final_out_path: Option<PathBuf> = None;

        for i in 0..module.num_of_txx {
            let (module_file, module_data) = get_sec_file(&file, &key)?;
            if !module_file.name().starts_with(&module.module_name()) {
                return Err(format!("Module file {} does not start with the module's name: {}!", module_file.name(), module.module_name()).into());
            }    
            println!("  Segment #{}/{} - Name: {}, Size: {}", i+1, module.num_of_txx, module_file.name(), module_file.size());

            let mut module_reader = Cursor::new(module_data);
            let _com_header: ModuleComHeader = module_reader.read_be()?;
            //if com_header.download_id != DOWNLOAD_ID {            it seems this can differ in some files
            //    return Err("Invalid module com_header!".into());
            //}

            let module_header: ModuleHeader = module_reader.read_be()?;
            let mut module_data = read_exact(&mut module_reader, module_header.cmp_size as usize)?;
            if module_header.is_ciphered() {
                println!("      - Deciphering...");
                module_data = decipher(&module_data);
            }
            if module_header.is_compressed() {
                println!("      - Decompressing...");
                module_data = decompress_zlib(&module_data)?;
            }

            let mut content_reader = Cursor::new(module_data);
            let content_header: ContentHeader = content_reader.read_be()?;
            println!("      --> 0x{:X} @ 0x{:X}", content_header.size, content_header.dest_offset());
            
            let output_path: PathBuf;
            if content_header.has_subfile() {
                let sub_filename_bytes = read_exact(&mut content_reader, 0x100)?;
                let sub_filename = common::string_from_bytes(&sub_filename_bytes);
                println!("      --> {}", sub_filename);

                let sub_folder_path = Path::new(&app_ctx.output_dir).join(module.module_name());
                fs::create_dir_all(&sub_folder_path)?;
                output_path = Path::new(&sub_folder_path).join(sub_filename);

            } else {
                output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", module.module_name()));
            }
            final_out_path = Some(output_path.clone());

            let data = read_exact(&mut content_reader, content_header.size as usize)?;
            let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
            out_file.seek(SeekFrom::Start(content_header.dest_offset() as u64))?;
            out_file.write_all(&data)?;

        }

        if app_ctx.has_option("sddl_sec:split_peaks") && module.module_name() == "PEAKS" {
            println!("\n- Splitting PEAKS");
            if let Some(ref path) = final_out_path {
                split_peaks_file(path, &app_ctx.output_dir, !app_ctx.has_option("sddl_sec:no_decomp_peaks"))?;
            }
        }
    }

    Ok(())
}
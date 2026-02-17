//sddl_dec 6.0 https://github.com/theubusu/sddl_dec
mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};
use crate::utils::compression::{decompress_zlib};
use include::*;

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

fn get_sec_file(mut file: &File) -> Result<(FileHeader, Vec<u8>), Box<dyn std::error::Error>> {
    let mut hdr_reader = Cursor::new(decrypt_aes128_cbc_pcks7(&common::read_exact(&mut file, 32)?, &DEC_KEY, &DEC_IV)?);
    let file_header: FileHeader = hdr_reader.read_be()?;
    let file_data = decrypt_aes128_cbc_pcks7(&common::read_exact(&mut file, file_header.size() as usize)?, &DEC_KEY, &DEC_IV)?;

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
    file.seek(SeekFrom::Start(0))?;
    let mut secfile_hdr_reader = Cursor::new(decipher(&common::read_exact(&mut file, 32)?));
    let secfile_header: SecHeader = secfile_hdr_reader.read_be()?;

    println!("File info -\nKey ID: {}\nGroup count: {}\nModule file count: {}\n", secfile_header.key_id(), secfile_header.grp_num(), secfile_header.prg_num());
    fs::create_dir_all(&app_ctx.output_dir)?;

    let (tdi_file, tdi_data) = get_sec_file(&file)?;
    println!("[TDI] Name: {}, Size: {}", tdi_file.name(), tdi_file.size());
    //if save_extra { //Save SDIT
    //    let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&output_folder).join(tdi_file.name()))?;
    //    out_file.write_all(&tdi_data)?;
    //}
    if tdi_file.name() != TDI_FILENAME {
        return Err(format!("Invalid TDI filename {}!, expected: {}", tdi_file.name(), TDI_FILENAME).into());
    }
    //parse TDI
    let modules = parse_tdi_to_modules(tdi_data)?;

    //get info files, each info file belongs to its respecitve group in the TDI
    for i in 0..secfile_header.grp_num() {
        let (info_file, info_data) = get_sec_file(&file)?;
        println!("\n[INFO] ID: {}, Name: {}, Size: {}", i, info_file.name(), info_file.size());
        if !info_file.name().ends_with(INFO_FILE_EXTENSION) {
            return Err(format!("Info file {} does not have the expected extension {}!", info_file.name(), INFO_FILE_EXTENSION).into());
        }
        //if save_extra { //Save info file
        //    let mut out_file = OpenOptions::new().write(true).create(true).open(Path::new(&output_folder).join(info_file.name()))?;
        //    out_file.write_all(&info_data)?;
        //}
        //print info file
        println!("{}", String::from_utf8_lossy(&info_data));
    }

    //parse module data
    for (i, module) in modules.iter().enumerate(){
        println!("\nModule #{}/{} - {}, Target ID: {}, Segment count: {}, Version: {}", 
                i+1, &modules.len(), module.module_name(), module.target_id, module.num_of_txx, module.version_string());

        for i in 0..module.num_of_txx {
            let (module_file, module_data) = get_sec_file(&file)?;
            if !module_file.name().starts_with(&module.module_name()) {
                return Err(format!("Module file {} does not start with the module's name: {}!", module_file.name(), module.module_name()).into());
            }    
            println!("  Segment #{}/{} - Name: {}, Size: {}", i+1, module.num_of_txx, module_file.name(), module_file.size());

            let mut module_reader = Cursor::new(module_data);
            let com_header: ModuleComHeader = module_reader.read_be()?;
            if com_header.download_id != DOWNLOAD_ID {
                return Err("Invalid module com_header!".into());
            }

            let module_header: ModuleHeader = module_reader.read_be()?;
            let mut module_data = common::read_exact(&mut module_reader, module_header.cmp_size as usize)?;
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
                let sub_filename_bytes = common::read_exact(&mut content_reader, 0x100)?;
                let sub_filename = common::string_from_bytes(&sub_filename_bytes);
                println!("      --> {}", sub_filename);

                let sub_folder_path = Path::new(&app_ctx.output_dir).join(module.module_name());
                fs::create_dir_all(&sub_folder_path)?;
                output_path = Path::new(&sub_folder_path).join(sub_filename);

            } else {
                output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", module.module_name()));
            }

            let data = common::read_exact(&mut content_reader, content_header.size as usize)?;
            let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
            out_file.seek(SeekFrom::Start(content_header.dest_offset() as u64))?;
            out_file.write_all(&data)?;

        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
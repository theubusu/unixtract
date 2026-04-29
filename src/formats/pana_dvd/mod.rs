mod include;
mod pana_dvd_crypto;
mod lzss;
mod util;
use std::any::Any;
use crate::AppContext;

use std::path::{Path, PathBuf};
use std::fs::{self, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::keys;
use crate::utils::common;
use crate::utils::global::opt_dump_dec_hdr;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::utils::compression::{decompress_gzip_get_filename};
use pana_dvd_crypto::{decrypt_data};
use lzss::{decompress_lzss};
use include::*;
use util::split_main_file;

pub struct PanaDvdContext {
    matching_key: [u8; 8],
    base_hdr_size: u32,
    is_aes: bool,
    aes_key: Option<[u8; 16]>,
    aes_iv: Option<[u8; 16]>
}

pub fn is_pana_dvd_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let header = common::read_file(&file, 0, 64)?;
    if let Some(matching_key) = find_key(&keys::PANA_DVD_KEYONLY, &header, b"PROG", 0)? {
        Ok(Some(Box::new(PanaDvdContext {
            matching_key: matching_key,
            base_hdr_size: 0,
            is_aes: false,
            aes_key: None, 
            aes_iv: None,
        })))
    } else if header.starts_with(b"PANASONIC\x00\x00\x00") && let Some(matching_key) = find_key(&keys::PANA_DVD_KEYONLY, &header, b"PROG", 48)? {
        Ok(Some(Box::new(PanaDvdContext {
            matching_key: matching_key,
            base_hdr_size: 48,
            is_aes: false,
            aes_key: None, 
            aes_iv: None,
        })))
    } else if let Some((aes_key, aes_iv, matching_key)) = find_aes_key_pair(&keys::PANA_DVD_AESPAIR, &header, b"PANASONIC", 32)? {
        Ok(Some(Box::new(PanaDvdContext {
            matching_key: matching_key,
            base_hdr_size: 48,
            is_aes: true,
            aes_key: Some(aes_key), 
            aes_iv: Some(aes_iv),
        })))
    } else {
        Ok(None)
    }
}

pub fn extract_pana_dvd(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let context = ctx.downcast::<PanaDvdContext>().expect("Missing context");

    let matching_key = context.matching_key;
    let mut file_entries: Vec<FileEntry> = Vec::new();

    //AES files can contain multiple firmwares inside of itself
    if context.is_aes {
        let (aes_key, aes_iv) = (context.aes_key.unwrap(), context.aes_iv.unwrap());
        println!("Using key: {} + AES key: {}, IV: {}", hex::encode_upper(matching_key), hex::encode_upper(aes_key), hex::encode_upper(aes_iv));

        //read inner file table
        let file_table = common::read_exact(&mut file, 48)?;
        let file_table_dec_aes = decrypt_aes128_cbc_nopad(&file_table, &aes_key, &aes_iv)?;
        let mut file_table_reader = Cursor::new(decrypt_data(&file_table_dec_aes, &matching_key));
        
        for _i in 0..4 {
            let file_entry: AesHeaderFileEntry = file_table_reader.read_le()?;
            if file_entry.size == 0 && file_entry.offset == 0 {
                break
            }
            //ignore duplicate entries
            if !file_entries.iter().any(|f| f.offset == file_entry.offset ){
                file_entries.push(FileEntry { offset: file_entry.offset, size: file_entry.size, header_size: context.base_hdr_size });
            } 
        }

    } else {
        println!("Using key: {}", hex::encode_upper(matching_key));
        file_entries.push(FileEntry { offset: 0, size: file.metadata()?.len() as u32, header_size: context.base_hdr_size });
    }

    println!("File contains {} sub-files...", file_entries.len());
    for (i, file_entry ) in file_entries.iter().enumerate() {
        let data = common::read_file(&mut file, file_entry.offset as u64, file_entry.size as usize)?;
        let dec_data = if context.is_aes {
            let (aes_key, aes_iv) = (context.aes_key.unwrap(), context.aes_iv.unwrap());
            decrypt_aes128_cbc_nopad(&data, &aes_key, &aes_iv)?
        } else {
            data
        };

        let mut file_reader = Cursor::new(dec_data);

        let output_dir = if file_entries.len() == 1 {
            &app_ctx.output_dir
        } else {
            &app_ctx.output_dir.join(format!("file_{}", i + 1))
        };

        println!("\nExtracting file {}/{} - Offset: {}, Size: {}, Header size: {}", 
                i + 1, file_entries.len(), file_entry.offset, file_entry.size, file_entry.header_size);
        
        extract_file(app_ctx, &mut file_reader, file_entry.header_size as u64, matching_key, output_dir)?;
    }

    Ok(())
}

fn extract_file(app_ctx: &AppContext, file_reader: &mut Cursor<Vec<u8>>, header_size: u64, key: [u8; 8], output_folder: &PathBuf) -> Result<(), Box<dyn std::error::Error>> { 
    let enc_list = common::read_exact(file_reader, LIST_SIZE)?;
    let dec_list = decrypt_data(&enc_list, &key);
    opt_dump_dec_hdr(app_ctx, &dec_list, "module_list")?;

    let mut list_reader = Cursor::new(dec_list);
    list_reader.seek(SeekFrom::Start(header_size))?;

    let mut modules: Vec<ModuleEntry> = Vec::new();

    for i in 0..100 {
        let entry: ModuleEntry = list_reader.read_le()?;
        if !entry.is_valid() {break};
        println!("Module {} - Name: {}, Version: {}, Model ID: {}, ID: {}, Offset: {}, Size: {}",
                i + 1, entry.name(), entry.version(), entry.model_id(), entry.id(), entry.offset, entry.size);
        if modules.iter().any(|m| m.offset == entry.offset ){
            println!("- Duplicate module, skipping!");
            continue
        }

        modules.push(entry);
    }

    let mut mod_i = 0;
    for module in &modules {
        mod_i += 1;
        println!("\n({}/{}) - {}, Offset: {}, Size: {}, Checksum: {:#010x}",
                mod_i, modules.len(), module.name(), module.offset, module.size, module.data_checksum);

        //if there is multiple modules with the same name, add the module ID to the outptut file to prevent collision
        let output_path = if modules.iter().filter(|m| m.name() == module.name()).nth(1).is_some() {
            Path::new(&output_folder).join(format!("{}_{}.bin", mod_i, module.name()))
        } else {
            Path::new(&output_folder).join(format!("{}.bin", module.name()))
        };
        
        file_reader.seek(SeekFrom::Start(module.offset as u64))?;

        //special treatment of MAIN
        if module.name() == "MAIN" {
            println!("- Extracting MAIN...");
            extract_main(file_reader, key, &output_path)?;
            if app_ctx.has_option("pana_dvd:split_main") {
                println!("\n- Splitting MAIN...");
                split_main_file(&output_path, output_folder)?;
            }
            continue
        }

        let data = common::read_exact(file_reader, (module.size as usize + 7) & !7)?;  //read to the nearest multiple of 8 (needed for unalinged data decryption)
        
        println!("- Decrypting...");
        let mut dec_data = decrypt_data(&data, &key);
        dec_data.truncate(module.size as usize); //discard padding

        if module.name().starts_with("DRV") {
            println!("- Extracting DRIVE firmware...");
            dec_data = extract_drv(dec_data, &key)?;
        }
        
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&dec_data)?;
        
        println!("-- Saved file!");
    }

    Ok(())
}

fn extract_main(file_reader: &mut Cursor<Vec<u8>>, key: [u8; 8], output_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let main_list_hdr: MainListHeader = file_reader.read_le()?;
    if main_list_hdr.entry_count() > 200 {
        println!("Unsupported MAIN data, skipping!");
        return Ok(())
    }

    println!("MAIN - Entry count: {}, Decompressed part size: {}", main_list_hdr.entry_count(), main_list_hdr.decompressed_part_size);
    let mut main_entries: Vec<MainListEntry> = Vec::new();
    for i in 0..main_list_hdr.entry_count() {
        let main_entry: MainListEntry = file_reader.read_le()?;
        println!("- Entry {}/{} - Size: {}, Checksum: {:#010x}",
                i + 1, main_list_hdr.entry_count(), main_entry.size, main_entry.checksum);
        main_entries.push(main_entry);
    }

    let mut maine_i = 0;
    let mut main_out_file = OpenOptions::new().write(true).create(true).truncate(true).open(&output_path)?;
    for entry in &main_entries {
        maine_i += 1;
        let mut data = common::read_exact(file_reader, entry.size as usize)?;
        let decrypt_size: usize = if main_list_hdr.decompressed_part_size == 0x2000000 {10240} /* old type */ else {5120};
        if entry.size > decrypt_size as u32 {
            //decrypt first and last 5kb
            let first_decrypted = decrypt_data(&data[..decrypt_size], &key);
            data[..decrypt_size].copy_from_slice(&first_decrypted);

            let last_decrypted = decrypt_data(&data[entry.size as usize - decrypt_size..], &key);
            data[entry.size as usize - decrypt_size..].copy_from_slice(&last_decrypted);
            //
        } else {
            let decrypted = decrypt_data(&data, &key);
            data.copy_from_slice(&decrypted);
        }
        
        print!("\nMAIN ({}/{}) - ", maine_i, main_entries.len());
        let decompressed_data = decompress_data(&data)?;
           
        main_out_file.write_all(&decompressed_data)?;
        
        println!("-- Saved to MAIN!");
    }

    Ok(())
}

fn decompress_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data_reader = Cursor::new(data);
    let header: CompressedFileHeader = data_reader.read_le()?;
    let compression_type = CompressionType::from(header.compression_type);

    println!("Compressed size: {}, Decompressed size: {}, Compression type: {:?}({})", 
            header.src_size, header.dest_size, compression_type, header.compression_type);

    let compressed_data = common::read_exact(&mut data_reader, header.src_size as usize)?;
    let mut decompressed_data;

    if compression_type == CompressionType::Gzip {
        println!("- Decompressing GZIP...");
        let (decompressed_gzip, gzip_filename) = decompress_gzip_get_filename(&compressed_data)?;
        if let Some(gzip_filename) = gzip_filename {
            println!("- GZIP filename: {}", gzip_filename);
        }    
        decompressed_data = decompressed_gzip;
    
    } else if compression_type == CompressionType::Lzss {
        println!("- Decompressing LZSS...");
        decompressed_data = decompress_lzss(&compressed_data);
        if decompressed_data.len() != header.dest_size as usize {
            return Err("Decompressed size does not match size in header, decompression failed!".into());
        }

    } else if compression_type == CompressionType::None {
        decompressed_data = compressed_data;
            
    //GzipAndLzss is not used in this context.
    } else {
        println!("- Unknown compression method!");
        decompressed_data = compressed_data;
    }

    // the decompressed data can have another header
    if decompressed_data.starts_with(COMPRESSED_FILE_MAGIC) {
        decompressed_data = decompress_data(&decompressed_data)?;
    }

    Ok(decompressed_data)
}

fn extract_drv(mut data: Vec<u8>, key: &[u8; 8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data_size = data.len();
    let decrypt_size: usize = 10240;
    let header_size = 0x20;

    //decrypt first and last 10240b (execpt last 48b)
    let first_decrypted = decrypt_data(&data[..decrypt_size], &key);
    data[..decrypt_size].copy_from_slice(&first_decrypted);

    let last_decrypted = decrypt_data(&data[data_size as usize - decrypt_size - 48..data_size - 48], &key);
    data[data_size as usize - decrypt_size - 48..data_size - 48].copy_from_slice(&last_decrypted);

    let mut reader = Cursor::new(&data);
    let header: DriveHeader = reader.read_le()?;
    println!("- DRIVE info:\n-- Manufacturer ID: {}\n-- Model: {}\n-- Version: {}", header.manufacturer(), header.model(), header.version());

    //can be compressed
    let out_data = if data[header_size..].starts_with(COMPRESSED_FILE_MAGIC) {
        decompress_data(&data[header_size..])?
    } else {
        data[header_size..].to_vec()
    };
    
    Ok(out_data)
}
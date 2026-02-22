mod include;
use std::any::Any;
use crate::AppContext;

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::io::{Write, Cursor};
use binrw::BinReaderExt;

use crate::utils::common;
use crate::utils::global::opt_dump_dec_hdr;
use crate::keys;
use crate::formats::epk::{decrypt_aes_ecb_auto, find_key};
use include::*;

pub fn is_epk3_file(_app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    Ok(None)
}

pub fn extract_epk3(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let stored_header = common::read_exact(&mut file, 1712)?;
    let header: Vec<u8>;
    let _header_signature;

    let mut new_type = false;
    let matching_key: Option<Vec<u8>>;
    println!("Finding key...");

    // find the key, knowing that the header should start with "EPK3" (old type 128 byte signature)
    if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &stored_header[128..], b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        _header_signature = &stored_header[..128];
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header[128..])?;
        opt_dump_dec_hdr(app_ctx, &header, "header")?;

    //try for new format epk3 (new type 256 byte signature)
    } else if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &stored_header[256..], b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        _header_signature = &stored_header[..256];
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header[256..])?;
        opt_dump_dec_hdr(app_ctx, &header, "header")?;
        new_type = true;

    } else {
        return Err("No valid key found!".into());
    }

    let signature_size = if new_type {256} else {128};
    let extra_segment_size = if new_type {4} else {0};

    let matching_key_bytes = matching_key.as_ref().unwrap();

    //parse header
    let mut hdr_reader = Cursor::new(header);
    let hdr: Header = hdr_reader.read_le()?;

    println!("\nEPK info -\nEPK3 type: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}.{:02x?}\nPackage Info size: {}", 
                if new_type {"New"} else {"Old"}, hdr.ota_id(), hdr.version[3], hdr.version[2], hdr.version[1], hdr.version[0], hdr.package_info_size);

    if new_type {
        let ex_hdr: HeaderNewEx = hdr_reader.read_le()?;
        println!("Encrypt type: {}\nUpdate type: {}\nUpdate platform version: {:.6}\nCompatible minimum version: {:.6}\nNeed to check compatible version: {}",
                ex_hdr.encrypt_type(), ex_hdr.update_type(), ex_hdr.update_platform_version, ex_hdr.compatible_minimum_version, ex_hdr.need_to_check_compatible_version);
    }

    println!();
    
    let _platform_versions = common::read_exact(&mut file, 36)?;
    let _pkg_info_signature = common::read_exact(&mut file, signature_size)?;

    //PKG INFO
    let pkg_info_encrypted = common::read_exact(&mut file, hdr.package_info_size as usize)?;
    let pkg_info = decrypt_aes_ecb_auto(matching_key_bytes, &pkg_info_encrypted)?;
    opt_dump_dec_hdr(app_ctx, &pkg_info, "pkg_info")?;

    let mut pkg_info_reader = Cursor::new(pkg_info);
    let pkg_info_hdr: PkgInfoHeader = pkg_info_reader.read_le()?;

    println!("Package info list size: {}\nPackage info count: {}", 
                pkg_info_hdr.package_info_list_size, pkg_info_hdr.package_info_count);

    if new_type {let _unknown = common::read_exact(&mut pkg_info_reader, 4)?;}; //new type has additional value

    let mut pak_i = 1;
    while (pkg_info_reader.position() as usize) < pkg_info_reader.get_ref().len() {
        let mut entry: PkgInfoEntry = pkg_info_reader.read_le()?;

        println!("\n({}) - {}, Size: {}, Segments: {}",
                pak_i, entry.package_name(), entry.package_size, entry.segment_count);
        
        for i in 0..entry.segment_count {
            if i > 0 {
                entry = pkg_info_reader.read_le()?;
            }   
            
            println!("- Segment {}/{}, Size: {}", entry.segment_index + 1, entry.segment_count, entry.segment_size);

            let _segment_signature = common::read_exact(&mut file, signature_size)?;

            let encrypted_data = common::read_exact(&mut file, entry.segment_size as usize + extra_segment_size)?;
            let out_data = decrypt_aes_ecb_auto(matching_key_bytes, &encrypted_data)?;

            let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", entry.package_name()));
            fs::create_dir_all(&app_ctx.output_dir)?;
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data[extra_segment_size..])?;

            println!("-- Saved to file!");
        }
        pak_i += 1;
    }

    Ok(())
}
use std::fs::{self, File, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom, Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::epk::{decrypt_aes_ecb_auto, find_key};

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //EPK3
    #[br(count = 4)] version: Vec<u8>,
	#[br(count = 32)] ota_id_bytes: Vec<u8>,
    package_info_size: u32,
    _bchunked: u32,
}
impl Header {
    fn ota_id(&self) -> String {
        common::string_from_bytes(&self.ota_id_bytes)
    }
}

#[derive(BinRead)]
struct HeaderNewEx {
    #[br(count = 4)] _pak_info_magic: Vec<u8>,
    #[br(count = 6)] encrypt_type_bytes: Vec<u8>,
    #[br(count = 6)] update_type_bytes: Vec<u8>,
    update_platform_version: f32,
    compatible_minimum_version: f32,
    need_to_check_compatible_version: i32,
}
impl HeaderNewEx {
    fn encrypt_type(&self) -> String {
        common::string_from_bytes(&self.encrypt_type_bytes)
    }
    fn update_type(&self) -> String {
        common::string_from_bytes(&self.update_type_bytes)
    }
}


#[derive(BinRead)]
struct PkgInfoHeader {
    package_info_list_size: u32,
    package_info_count: u32,
}

#[derive(BinRead)]
struct PkgInfoEntry {
    _package_type: u32,
    _package_info_size: u32,
    #[br(count = 128)] package_name_bytes: Vec<u8>,
    #[br(count = 96)] _package_version_bytes: Vec<u8>,
	#[br(count = 32)] _package_architecture_bytes: Vec<u8>,
    #[br(count = 32)] _checksum: Vec<u8>,
    package_size: u32,
    _dipk: u32,
    //segment info
    _is_segmented: u32,
    segment_index: u32,
    segment_count: u32,
    segment_size: u32,
    //
    _unk: u32,
}
impl PkgInfoEntry {
    fn package_name(&self) -> String {
        common::string_from_bytes(&self.package_name_bytes)
    }
}

pub fn extract_epk3(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(128))?; //inital signature

    let stored_header = common::read_exact(&mut file, 1584)?; //max header size
    let header: Vec<u8>;

    let mut new_type = false;

    let matching_key: Option<Vec<u8>>;
    println!("Finding key...");

    // find the key, knowing that the header should start with "EPK3"
    if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &stored_header, b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;

    //try for new format epk3 where theres an additional 128byte signature at the beginning
    } else if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &stored_header[128..], b"EPK3")? {
        println!("Found valid key: {}", key_name);
        matching_key = Some(key_bytes);
        header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;
        new_type = true;

    } else {
        println!("No valid key found!");
        return Ok(());
    }

    let signature_size = if new_type {256} else {128};
    let extra_segment_size = if new_type {4} else {0};

    let matching_key_bytes = matching_key.as_ref().unwrap();

    //parse header
    let mut hdr_reader = Cursor::new(header);
    if new_type {let _signature = common::read_exact(&mut hdr_reader, 128)?;};
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
    let _signature = common::read_exact(&mut file, signature_size)?;

    //PKG INFO
    let pkg_info_encrypted = common::read_exact(&mut file, hdr.package_info_size as usize)?;
    let pkg_info = decrypt_aes_ecb_auto(matching_key_bytes, &pkg_info_encrypted)?;
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

            let _signature = common::read_exact(&mut file, signature_size)?;

            let encrypted_data = common::read_exact(&mut file, entry.segment_size as usize + extra_segment_size)?;
            let out_data = decrypt_aes_ecb_auto(matching_key_bytes, &encrypted_data)?;

            let output_path = Path::new(&output_folder).join(format!("{}.bin", entry.package_name()));
            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data[extra_segment_size..])?;

            println!("-- Saved to file!");
        }
        pak_i += 1;
    }

    println!("\nExtraction finished!");
    Ok(())
}
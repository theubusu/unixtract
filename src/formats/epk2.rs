use std::any::Any;
use crate::{InputTarget, AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "epk2", detector_func: is_epk2_file, extractor_func: extract_epk2 }
}

use std::fs::{self, OpenOptions};
use std::path::{Path};
use std::io::{Write, Seek, SeekFrom, Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::keys;
use crate::formats::epk::{decrypt_aes_ecb_auto, find_key};

static SIGNATURE_SIZE: u32 = 128;

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //epak
    file_size: u32,
	pak_count: u32,
	#[br(count = 4)] _epk2_magic: Vec<u8>, //EPK2
	#[br(count = 4)] version: Vec<u8>,
	#[br(count = 32)] ota_id_bytes: Vec<u8>,
}
impl Header {
    fn ota_id(&self) -> String {
        common::string_from_bytes(&self.ota_id_bytes)
    }
}

#[derive(BinRead)]
struct PakEntry {
    offset: u32,
	size: u32,
	#[br(count = 4)] name_bytes: Vec<u8>,
	#[br(count = 4)] _version: Vec<u8>,
	segment_size: u32,
}
impl PakEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct PakHeader {
    #[br(count = 4)] _pak_name_bytes: Vec<u8>,
    image_size: u32,
    #[br(count = 64)] platform_id_bytes: Vec<u8>,
    _sw_version: u32,
    _sw_date: u32,
    _build_type: u32,
    segment_count: u32,
    segment_size: u32,
    segment_index: u32,
    #[br(count = 4)] _pak_magic_bytes: Vec<u8>, //MPAK
    #[br(count = 24)] _reserved: Vec<u8>,
    _segment_crc32: u32,
}
impl PakHeader {
    fn platform_id(&self) -> String {
        common::string_from_bytes(&self.platform_id_bytes)
    }
}

struct Pak {
    offset: u32,
    _size: u32,
    name: String,
}

pub fn is_epk2_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match &app_ctx.input {InputTarget::File(f) => f, InputTarget::Directory(_) => return Ok(None)};

    let header = common::read_file(&file, 128, 4)?;
    if header == b"epak" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_epk2(app_ctx: &AppContext, _: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = match &app_ctx.input {InputTarget::File(f) => f, InputTarget::Directory(_) => return Err("Extractor expected file, not directory".into())};

    let _header_signature = common::read_exact(&mut file, SIGNATURE_SIZE as usize)?;
    let stored_header = common::read_exact(&mut file, 1584)?; //max header size
    let header;

    let mut matching_key: Option<Vec<u8>> = None;

    //check if header is encrypted
    let epak = &stored_header[0..4]; // epak magic
    if epak == b"epak" {
        println!("Header is not encrypted.");
        header = stored_header;
    } else {
        println!("Header is encrypted...");
        println!("\nFinding key...");
        //find the key, knowing that the header should start with "epak"
        if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &stored_header, b"epak")? {
            println!("Found valid key: {}", key_name);
            matching_key = Some(key_bytes);
            header = decrypt_aes_ecb_auto(matching_key.as_ref().unwrap(), &stored_header)?;
        } else {
            println!("No valid key found!");
            return Ok(());
        }    
    }
    //parse header
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("\nEPK info -\nData size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}.{:02x?}\n", 
                hdr.file_size, hdr.pak_count, hdr.ota_id(), hdr.version[3], hdr.version[2], hdr.version[1], hdr.version[0]);
 
    let mut paks: Vec<Pak> = Vec::new();
    //parse paks in header
    for i in 0..hdr.pak_count {
        let pak: PakEntry = hdr_reader.read_le()?;
        //here the accounted for signature is the one at the beginning of the EPK file
        println!("Pak {} - {}, offset: {}, size: {}, segment size: {}", i + 1, pak.name(), pak.offset + SIGNATURE_SIZE, pak.size, pak.segment_size);
        paks.push(Pak { offset: pak.offset + SIGNATURE_SIZE, _size: pak.size, name: pak.name() });
    }

    let mut signature_count = 0;
    //extract paks
    for (pak_n, pak) in paks.iter().enumerate() {     
        let actual_offset = pak.offset + (SIGNATURE_SIZE * signature_count);
        file.seek(SeekFrom::Start(actual_offset as u64))?;

        let mut _segment_signature = common::read_exact(&mut file, SIGNATURE_SIZE as usize)?;
        signature_count += 1;

        let encrypted_header = common::read_exact(&mut file, 128)?;

        //the file's header was not encrypted so we dont have the key yet
        if matching_key.is_none() {
            println!("\nFinding key...");
            //find the key, knowing that the header should start with with the paks name
            if let Some((key_name, key_bytes)) = find_key(&keys::EPK, &encrypted_header, pak.name.as_bytes())? {
                println!("Found correct key: {}", key_name);
                matching_key = Some(key_bytes);
            } else {
                println!("No valid key found!");
                return Ok(());
            }
        }
        let matching_key_bytes = matching_key.as_ref().unwrap();

        let mut pak_header_reader = Cursor::new(decrypt_aes_ecb_auto(&matching_key_bytes, &encrypted_header)?);
        let mut pak_header: PakHeader = pak_header_reader.read_le()?;

        println!("\n({}/{}) - {}, Size: {}, Segment count: {}, Platform: {}",
                pak_n + 1, paks.len(), pak.name, pak_header.image_size, pak_header.segment_count, pak_header.platform_id());

        for i in 0..pak_header.segment_count {
            // for first segment we already read the header so skip doing that for it
            if i > 0 {
                _segment_signature = common::read_exact(&mut file, 128)?;
                signature_count += 1;

                let encrypted_header = common::read_exact(&mut file, 128)?;
                let mut pak_header_reader = Cursor::new(decrypt_aes_ecb_auto(&matching_key_bytes, &encrypted_header)?);
                pak_header = pak_header_reader.read_le()?;
            }

            assert!(i == pak_header.segment_index, "Unexpected segment index in pak header!, expected: {}, got: {}", i , pak_header.segment_index);

            let actual_segment_size = 
            // check if this is the last segment and not the last PAK
            if i == pak_header.segment_count - 1 && pak_n < paks.len() - 1{
                // calculate distance to next PAK
                let next_pak_offset = &paks[pak_n + 1].offset + (SIGNATURE_SIZE * signature_count);
                let current_pos = file.stream_position()?;
                let distance = next_pak_offset - current_pos as u32;
                
                // if distance less than segment size, use the distance as actual size
                if distance < pak_header.segment_size {
                    distance
                } else {
                    pak_header.segment_size
                }

            } else {
                pak_header.segment_size
            };

            println!("- Segment {}/{} - Size: {}", i + 1, pak_header.segment_count, actual_segment_size);

            let segment_data = common::read_exact(&mut file, actual_segment_size as usize)?;
            let out_data = decrypt_aes_ecb_auto(&matching_key_bytes, &segment_data)?;

            let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", pak.name));
            fs::create_dir_all(&app_ctx.output_dir)?;
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data)?;

            println!("-- Saved to file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}
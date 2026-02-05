use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "invincible_image", detector_func: is_invincible_image_file, extractor_func: extract_invincible_image }
}

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Seek, SeekFrom, Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::utils::common;

#[derive(BinRead)]
struct Header {
    #[br(count = 16)] _magic_bytes: Vec<u8>,
    #[br(count = 4)] file_version: Vec<u8>,
    _unk1: u32,
    #[br(count = 16)] ver1_bytes: Vec<u8>,
    #[br(count = 16)] ver2_bytes: Vec<u8>,
    _unk2: u16,
    _type: u8,
    keep_size: u32,
    _unk3: u8,
    data_start_offset: u32,
    data_size: u32,
    _data_size_2: u32,
    skip_size: u32,
    _unk4: u16,
    _encryption_method: u8, // 0x01 - AES128, 0x02 - AES256
    _hash_type: u8, // 0x01 - MD5, 0x02 - SHA1
    #[br(count = 16)] ver3_bytes: Vec<u8>,
    #[br(count = 16)] ver4_bytes: Vec<u8>,
    #[br(count = 11)] _unk6: Vec<u8>,
    payload_count: u8,
}
impl Header {
    fn ver1(&self) -> String {
        common::string_from_bytes(&self.ver1_bytes).replace('\n', "")
    }
    fn ver2(&self) -> String {
        common::string_from_bytes(&self.ver2_bytes).replace('\n', "")
    }
    fn ver3(&self) -> String {
        common::string_from_bytes(&self.ver3_bytes).replace('\n', "")
    }
    fn ver4(&self) -> String {
        common::string_from_bytes(&self.ver4_bytes).replace('\n', "")
    }
}

#[derive(BinRead)]
struct Entry {
    #[br(count = 16)] name_bytes: Vec<u8>,
    start_offset: u32,
    size: u32,
}
impl Entry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

pub fn is_invincible_image_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let header = common::read_file(app_ctx.file, 0, 16)?;
    if header == b"INVINCIBLE_IMAGE" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_invincible_image(app_ctx: &AppContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file;
    let header: Header = file.read_le()?;

    println!("File info:\nFile Version: {}.{}\nVersion(1): {}\nVersion(2): {}\nVersion(3): {}\nVersion(4): {}\nData size: {}\nData start offset: {}\nKeep data size: {}\nSkip data size: {}\n\nPayload Count: {}",
            header.file_version[0], header.file_version[1], header.ver1(), header.ver2(), header.ver3(), header.ver4(), header.data_size, header.data_start_offset, header.keep_size, header.skip_size, header.payload_count);

    let mut entries: Vec<Entry> = Vec::new();

    for i in 0..header.payload_count {
        let entry: Entry = file.read_le()?;
        println!("{}. {}, Start offset: {}, Size: {}", 
                i + 1, entry.name(), entry.start_offset, entry.size);
        entries.push(entry);
    }

    if header.file_version[0] != 3 {
        println!("\nSorry, this version of the file is not supported!");
        return Ok(())
    }

    let mut encrypted_data = Vec::new();
    let mut buffer = vec![0u8; header.keep_size as usize];

    file.seek(SeekFrom::Start(header.data_start_offset.into()))?;

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // EOF
        }
        encrypted_data.extend_from_slice(&buffer[..bytes_read]);
        file.seek(SeekFrom::Current(header.skip_size.into()))?;
    }

    //v3 key + iv
    let key: [u8; 16] = [0x32, 0xe5, 0x26, 0x1e, 0x22, 0x67, 0x5e, 0x93, 0x20, 0xcf, 0x35, 0x91, 0x7c, 0x63, 0x7a, 0x36];
    let iv:  [u8; 16] = [0xe3, 0x9f, 0x36, 0x39, 0x56, 0x9a, 0x6b, 0x8d, 0x3f, 0x2e, 0xc9, 0x44, 0xd9, 0xbc, 0xec, 0x43];

    println!("\nDecrypting data...");
    let decrypted_data = decrypt_aes128_cbc_nopad(&encrypted_data, &key, &iv)?;

    let mut data_reader = Cursor::new(decrypted_data);

    let mut i = 1;
    for entry in entries {
        println!("\n({}/{}) - {}, Size: {}", i, header.payload_count, entry.name(), entry.size);
        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(app_ctx.output_dir).join(entry.name() + ".bin");

        fs::create_dir_all(app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");
        i += 1;
    }

    println!("\nExtraction finished!");

    Ok(())
}
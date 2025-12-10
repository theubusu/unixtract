use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Cursor, Seek};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::keys;

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] vendor_magic_bytes: Vec<u8>,
    #[br(count = 8)] _mtk_magic: Vec<u8>, //#DH@FiRm
	#[br(count = 60)] version_bytes: Vec<u8>,
	file_size: u32,
    _platform: u32,
    #[br(count = 32)] product_name_bytes: Vec<u8>,
    #[br(count = 32)] _unknown: Vec<u8>,
}
impl Header {
    fn vendor_magic(&self) -> String {
        common::string_from_bytes(&self.vendor_magic_bytes)
    }
    fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    fn product_name(&self) -> String {
        common::string_from_bytes(&self.product_name_bytes)
    }

}

#[derive(BinRead)]
struct PartEntry {
    #[br(count = 4)] name_bytes: Vec<u8>,
	flags: u32,
    size: u32,
}
impl PartEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn is_valid(&self) -> bool {
        self.name().is_ascii()
    }
    fn is_encrypted(&self) -> bool {
        (self.flags & 1 << 0) == 1 << 0
    }
}

static HEADER_KEY: [u8; 16] = [
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
];

static HEADER_IV: [u8; 16] = [0x00; 16];

pub fn is_mtk_pkg_file(file: &File) -> bool {
    let mut encrypted_header = common::read_file(&file, 0, 144).expect("Failed to read from file.");
    let mut header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV).expect("Decryption error!");
    if &header[4..12] == b"#DH@FiRm" {
        true
    } else {
        // try for philips which has additional 128 bytes at beginning
        encrypted_header = common::read_file(&file, 128, 144).expect("Failed to read from file.");
        header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV).expect("Decryption error!");
        if &header[4..12] == b"#DH@FiRm" {
            true
        } else {
            false

        }
    }
}

pub fn extract_mtk_pkg(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();
    let encrypted_header = common::read_exact(&mut file, 144)?;
    let header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV)?;
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {        
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        if !part_entry.is_valid() {
            break
        }

        println!("\n#{} - {}, Size: {} {}", part_n, part_entry.name(), part_entry.size, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize + 48)?;
        
        if part_entry.size == 0 {
            println!("- Empty entry, skipping!");
            continue
        }

        let mut out_data = Vec::new(); 
        if part_entry.is_encrypted() {
            let crypted_header = &data[..48];

            // try decrypting with vendor magic repeated 4 times (works for most)
            let mut key = [0u8; 16];
            for i in 0..4 {
                key[i * 4..(i + 1) * 4].copy_from_slice(&hdr.vendor_magic_bytes);
            }
            let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key, &HEADER_IV)?;

            if try_decrypt.starts_with(b"reserved mtk inc") {
                println!("- Decrypting with 4xVendor magic...");
                out_data = decrypt_aes128_cbc_nopad(&data[..data.len() & !15], &key, &HEADER_IV)?;
            } else { 
                //try decrypting with one of custom keys
                let mut decrypted = false;
                for (key_hex, iv_hex, name) in keys::MTK_PKG_CUST {
                    let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
                    let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
                    let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key_array, &iv_array)?;

                    if try_decrypt.starts_with(b"reserved mtk inc") {    
                        println!("- Decrypting with key {}...", name);
                        out_data = decrypt_aes128_cbc_nopad(&data[..data.len() & !15], &key_array, &iv_array)?;
                        decrypted = true;
                        break
                    }
                }

                if !decrypted {
                    println!("- Failed to decrypt data!");
                    continue
                }
            };  
        } else {
            out_data = data;
        }

        //strip iMtK thing
        let extra_header_len = if &out_data[48..52] == b"iMtK" {
            let imtk_len = u32::from_le_bytes(out_data[52..56].try_into().unwrap());
            imtk_len + 8
        } else {
            0
        };
        
        let output_path = Path::new(&output_folder).join(part_entry.name() + ".bin");
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&out_data[48 + extra_header_len as usize..])?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
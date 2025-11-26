use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::io::{Write, Seek, Read, Cursor};
use tar::Archive;
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad, decrypt_aes128_cbc_pcks7};

static FILE_KEY: [u8; 16] = [
        0x2A, 0x54, 0xA5, 0x30, 0xE0, 0x09, 0xA3, 0xDC,
        0x03, 0xFB, 0xC3, 0x5E, 0x23, 0xA2, 0xC1, 0x0D,
];

static FILE_IV: [u8; 16] = [0x00; 16];

#[derive(BinRead)]
struct ImageHeader {
    #[br(count = 8)] _empty: Vec<u8>,
    #[br(count = 8)] _magic_bytes: Vec<u8>, //imgARMcC
	#[br(count = 4)] _target_bytes: Vec<u8>,
    #[br(count = 4)] _platform_id: Vec<u8>,
    image_type: u32,
    size1: u32,
    _size2: u32,
    data_start_offset: u32,
    _data_link_address: u32,
    _data_entry_point_offset: u32,
    flags: u32,
    _timestamp: u32,
    #[br(count = 4)] _build_host: Vec<u8>,
    #[br(count = 4)] _unk: Vec<u8>,
    #[br(count = 192)] _rest_of_header: Vec<u8>,
}
impl ImageHeader {
    fn is_encrypted(&self) -> bool {
        self.flags == 0x80
    }
    fn type_string(&self) -> &str {
        if self.image_type == 0xa {
            return "initfs"
        } else if self.image_type == 0x18 {
            return "uImage"
        } else if self.image_type == 0x3 {
            return "loader"
        } else if self.image_type == 0xd {
            return "app_cramfs"
        } else if self.image_type == 0x6 {
            return "Customization Package"
        } else if self.image_type == 0xe {
            return "firmware_blob"
        } else {
            return "unknown"
        }
    }
}

pub fn is_roku_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 32).expect("Failed to read from file.");
    let try_decrypt_header = decrypt_aes128_cbc_nopad(&header, &FILE_KEY, &FILE_IV).expect("Decryption error!");

    if try_decrypt_header.starts_with(b"manifest\x00\x00\x00\x00\x00\x00\x00\x00") {
        true
    } else {
        false
    }
}

pub fn extract_roku(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    println!("\nDecrypting...\n");
    let tar_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &FILE_KEY, &FILE_IV)?;
    let tar_reader = Cursor::new(tar_data);
    let mut tar_archive = Archive::new(tar_reader);

    for entry_result in tar_archive.entries_with_seek()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();

        if path == std::path::Path::new("manifest") {
            let size = entry.header().size()? as usize;
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;

            let text = String::from_utf8_lossy(&contents[..size - 256]); //dont display signature
            println!("Manifest file:\n{}", text);
        } else {
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?; //entry cant seek
            
            if contents.starts_with(b"\x00\x00\x00\x00\x00\x00\x00\x00imgARMcC") {
                println!("\nImage file: {:?}:", path);
                let size = entry.header().size()? as usize;
                let mut image_reader = Cursor::new(contents);
                let mut i = 1;

                while image_reader.stream_position()? < size as u64 {
                    let image: ImageHeader = image_reader.read_le()?;
                    println!("\nImage {} - Type: {:x}({}), Size: {}, Flags: {:x}{}, Data offset: {}", 
                            i ,image.image_type, image.type_string(), image.size1, image.flags, if image.is_encrypted(){"(Encrypted)"}else{" "}, image.data_start_offset);
                    
                    let data = 
                    if image.data_start_offset == 0 {
                        common::read_exact(&mut image_reader, image.size1 as usize - 256)?
                    } else {
                        let _extra_data = common::read_exact(&mut image_reader, image.data_start_offset as usize - 256)?;
                        common::read_exact(&mut image_reader, image.size1 as usize - image.data_start_offset as usize)?
                    };

                    let folder_path = Path::new(&output_folder).join(&path);
                    let output_path = Path::new(&folder_path).join(format!("{}_{}.bin", i, image.type_string()));

                    fs::create_dir_all(&folder_path)?;
                    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                    out_file.write_all(&data)?;

                    println!("- Saved file!");

                    i += 1;
                }

            } else {
                println!("\nOther/Unknown file: {:?}", path);
                let output_path = Path::new(&output_folder).join(&path);

                fs::create_dir_all(&output_folder)?;
                let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                out_file.write_all(&contents)?;

                println!("- Saved file!");
            }
        }
    }

    println!("\nExtraction finished!");
    Ok(())
}
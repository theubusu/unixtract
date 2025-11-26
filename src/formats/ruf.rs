use std::path::{Path};
use std::fs::{self, File, OpenOptions};
use binrw::{BinRead, BinReaderExt};
use std::io::{Write, Seek, SeekFrom, Cursor};

use crate::utils::common;
use crate::keys;
use crate::utils::aes::{decrypt_aes128_cbc_pcks7};

#[derive(BinRead)]
struct RufHeader {
    #[br(count = 6)] _magic_bytes: Vec<u8>,
    #[br(count = 2)] _upgrade_type_bytes: Vec<u8>,
	_unk1: u32,
    #[br(count = 32)] date_time_bytes: Vec<u8>,
    #[br(count = 8)] buyer_bytes: Vec<u8>,
    #[br(count = 32)] model_bytes: Vec<u8>,
    #[br(count = 32)] region_info_bytes: Vec<u8>,
    #[br(count = 4)] version_bytes: Vec<u8>,
    data_size: u32,
    #[br(count = 20)] _unk2: Vec<u8>,
    dual_ruf_flag: u32,
    #[br(count = 44)] _unk3: Vec<u8>,
    payload_count: u16,
    _payload_entry_size: u16,
    payloads_start_offset: u32,
}
impl RufHeader {
    fn date_time(&self) -> String {
        common::string_from_bytes(&self.date_time_bytes)
    }
    fn buyer(&self) -> String {
        common::string_from_bytes(&self.buyer_bytes)
    }
    fn model(&self) -> String {
        common::string_from_bytes(&self.model_bytes)
    }
    fn region_info(&self) -> String {
        common::string_from_bytes(&self.region_info_bytes)
    }
    fn is_dual_ruf(&self) -> bool {
        if self.dual_ruf_flag == 0x44 {true} else {false}
    }
}

#[derive(BinRead)]
struct RufEntry {
    #[br(count = 32)] _metadata: Vec<u8>,
    payload_type_bytes: u32,
	size: u32,
    _unk1: u32,
    #[br(count = 20)] _unk2: Vec<u8>,
}
impl RufEntry {
    fn payload_type(&self) -> &str {
        if self.payload_type_bytes == 1 {
            return "squashfs"
        } else if self.payload_type_bytes == 2 {
            return "cfe"
        } else if self.payload_type_bytes == 3 {
            return "vmlinuz"
        } else if self.payload_type_bytes == 4 {
            return "loader"
        } else if self.payload_type_bytes == 5 {
            return "splash"
        } else {
            return "unknown"
        }
    }
}

pub fn is_ruf_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 3).expect("Failed to read from file.");
    if header == b"RUF" {
        true
    } else {
        false
    }
}

pub fn extract_ruf(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let header: RufHeader = file.read_be()?;
    if header.is_dual_ruf() {
        println!("\nDual RUF detected! Extracting 1st RUF...\n");
        actually_extract_ruf(&file, &format!("{}/RUF_1", output_folder), 0)?;
        println!("\nExtracting 2nd RUF...\n");
        actually_extract_ruf(&file, &format!("{}/RUF_2", output_folder), 41943088)?;
    } else {
        actually_extract_ruf(&file, &output_folder, 0)?;
    }

    println!("\nExtraction finished!");
    Ok(())
}

fn actually_extract_ruf(mut file: &File, output_folder: &str, start_offset: u64) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(start_offset))?;
    let header: RufHeader = file.read_be()?;

    println!("File info:\nBuyer: {} \nModel: {} \nRegion Info: {} \nDateTime: {}\nVersion:{:02x?} \nData Size: {} \nDual RUF: {}",
            header.buyer(), header.model(), header.region_info(), header.date_time(), header.version_bytes, header.data_size, header.is_dual_ruf());
    
    println!("\nPayload count: {}", header.payload_count);
    file.seek(SeekFrom::Start(start_offset + header.payloads_start_offset as u64))?;

    let mut entries: Vec<RufEntry> = Vec::new();

    let mut vi = 0;
    for _i in 0..28 {
        if vi == header.payload_count {
            break
        }
        let entry: RufEntry = file.read_be()?;

        if entry.payload_type_bytes == 0 && entry.size == 0 {
            continue
        } else {
            vi += 1
        }

        println!("{}/{}: Type: {}({}), Size: {}",
                vi, header.payload_count, entry.payload_type_bytes, entry.payload_type(), entry.size);
        
        entries.push(entry);
    }

    let mut key: Option<&str> = None;
    let key_bytes;
    let iv_bytes: [u8; 16] = [0x00; 16];

    //find key
    for (prefix, value) in keys::RUF {
        if header.model().starts_with(prefix) {
            key = Some(value);
            break;
        }
    }
    if let Some(k) = key {
        println!("\nKey: {}", k);
        key_bytes = hex::decode(k)?.as_slice().try_into()?;
    } else {
        println!("\nSorry, this firmware is not supported!");
        std::process::exit(1);
    }

    file.seek(SeekFrom::Start(start_offset + 2048))?;
    let encrypted_data = common::read_exact(&mut file, header.data_size as usize)?;
    println!("Decrypting data...");
    let decrypted_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &key_bytes, &iv_bytes)?;

    let mut data_reader = Cursor::new(decrypted_data);

    let mut ei = 1;
    for entry in entries {
        println!("\nEntry {}/{}: {} - {}, Size: {}",
            ei, header.payload_count, entry.payload_type_bytes, entry.payload_type(), entry.size);

        let data = common::read_exact(&mut data_reader, entry.size as usize)?;

        let output_path = Path::new(&output_folder).join(format!("{}_{}.bin", entry.payload_type_bytes, entry.payload_type()));
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
            
        out_file.write_all(&data)?;

        println!("- Saved file!");

        ei += 1;
    }

    Ok(())
}
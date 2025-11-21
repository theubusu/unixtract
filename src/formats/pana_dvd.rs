use std::fs::File;
use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Cursor, Seek, SeekFrom};

use simd_adler32::adler32;
use flate2::read::GzDecoder;
use binrw::{BinRead, BinReaderExt};

use crate::keys;
use crate::common;
use crate::utils::pana_dvd_crypto::{decrypt_data};
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::utils::lzss::{decompress_lzss};

#[derive(BinRead)]
struct ModuleEntry {
    #[br(count = 4)] name_bytes: Vec<u8>,
    #[br(count = 4)] version_bytes: Vec<u8>,
    _unk: u32,
    offset: u32,
    #[br(count = 8)] platform_bytes: Vec<u8>,
    _unk1: u16,
    #[br(count = 6)] id_bytes: Vec<u8>,
    size: u32,
    data_checksum: u32,
    _unk2: u32,
    _entry_checksum: u32,
}
impl ModuleEntry {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn version(&self) -> String {
        common::string_from_bytes(&self.version_bytes)
    }
    fn platform(&self) -> String {
        common::string_from_bytes(&self.platform_bytes)
    }
    fn id(&self) -> String {
        common::string_from_bytes(&self.id_bytes)
    }
    fn is_valid(&self) -> bool {
        self.name().is_ascii() && self.platform().is_ascii()
    }
}

#[derive(BinRead)]
struct MainListHeader {
    _checksum: u32,
    _unk: u32,
    list_size: u32,
    _unk2: u64,
}
impl MainListHeader {
    fn entry_count(&self) -> u32 {
        (&self.list_size - 20) / 8
    }
}

#[derive(BinRead)]
struct MainListEntry {
    size: u32,
    checksum: u32,
}

#[derive(BinRead)]
struct MainEntryHeader {
    #[br(count = 14)] _header_string: Vec<u8>, //EXTRHEADDRV
    compression_type_byte: u16,
    decompressed_size: u32,
    _destination_address: u32,
    compressed_size: u32,
    _unk: u32,
    _footer_offset: u32,
    _base_address: u32,
    _checksum: u32,
    _checksum_flag: u8,
    #[br(count = 19)] _unused: Vec<u8>,
}
impl MainEntryHeader {
    fn compression_type(&self) -> &str {
        if self.compression_type_byte == 0 {
            return "Uncompressed"
        } else if self.compression_type_byte == 1 {
            return "GZIP + LZSS"
        } else if self.compression_type_byte == 2 {
            return "LZSS"
        } else {
            return "Unknown"
        }
    }
}

pub fn find_key<'a>(key_array: &'a [&'a str], data: &[u8], expected_magic: &[u8]) -> Result<Option<[u8; 8]>, Box<dyn std::error::Error>> {
    for key_hex in key_array {
        let key_bytes = hex::decode(key_hex)?;
        let key_array: [u8; 8] = match key_bytes.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let decrypted = decrypt_data(data, &key_array);
     
        if decrypted.starts_with(expected_magic) {
            return Ok(Some(key_array));
        }
    }
    Ok(None)
}

pub fn find_aes_key_pair<'a>(key_array: &'a [(&'a str, &'a str)], data: &[u8], expected_magic: &[u8], magic_offset: usize) -> Result<Option<([u8; 16], [u8; 8])>, Box<dyn std::error::Error>> {
    for (aes_key_hex, cust_key_hex) in key_array {
        let aes_key_bytes = hex::decode(aes_key_hex)?;
        let aes_key_array: [u8; 16] = match aes_key_bytes.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let aes_decrypted = decrypt_aes128_cbc_nopad(data, &aes_key_array, iv)?;

        let key_bytes = hex::decode(cust_key_hex)?;
        let key_array: [u8; 8] = match key_bytes.as_slice().try_into() {
            Ok(k) => k,
            Err(_) => continue,
        };
        let decrypted = decrypt_data(&aes_decrypted, &key_array);
     
        if decrypted[magic_offset..].starts_with(expected_magic) {
            return Ok(Some((aes_key_array, key_array)));
        }
    }
    Ok(None)
}

pub fn is_pana_dvd_file(mut file: &File) -> bool {
    let header = common::read_file(&file, 0, 64).expect("Failed to read from file.");
    if header.starts_with(b"PANASONIC\x00\x00\x00") {
        file.seek(std::io::SeekFrom::Start(48)).expect("Failed to seek"); //skip rest of header
        true
    } else if find_key(&keys::PANA_DVD_KEYONLY, &header, b"PROG").expect("Failed to decrypt header.").is_some() {
        true
    } else if find_aes_key_pair(&keys::PANA_DVD_AESPAIR, &header, b"PANASONIC", 32).expect("Failed to decrypt header.").is_some() {
        true
    } else {
        false
    }
}

fn decompress_gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

pub fn extract_pana_dvd(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let init_pos = file.stream_position()?;
    file.seek(SeekFrom::Start(0))?;

    let mut data = Vec::new();  // we need to load the entire file into a cursor so we can swap it with AES decrypted data if its AES encrypted because im not making temp files
    file.read_to_end(&mut data)?;

    let mut file_reader = Cursor::new(data);
    file_reader.seek(SeekFrom::Start(init_pos))?;

    let enc_header = common::read_exact(&mut file_reader, 8192)?;
    let matching_key;
    let header;
    // find the key, knowing that the first entry is always "PROG"
    if let Some(key_array) = find_key(&keys::PANA_DVD_KEYONLY, &enc_header, b"PROG")? {
        println!("Found valid key: {}\n", hex::encode_upper(key_array));
        matching_key = Some(key_array);
        header = decrypt_data(&enc_header, &key_array);

    } else if let Some((aes_key_array, key_array)) = find_aes_key_pair(&keys::PANA_DVD_AESPAIR, &enc_header, b"PROG", 96)? {
        println!("Found AES key pair: aes={} cust={}", hex::encode_upper(aes_key_array), hex::encode_upper(key_array));
        matching_key = Some(key_array);
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        println!("Decrypting AES...\n");
        let aes_decrypted = decrypt_aes128_cbc_nopad(&file_reader.get_ref()[48..], &aes_key_array, iv)?;
        file_reader = Cursor::new(aes_decrypted); //set the file reader to use AES decrypted stream

        file_reader.seek(SeekFrom::Start(48))?;
        let enc_header = common::read_exact(&mut file_reader, 8192)?;
        header = decrypt_data(&enc_header, &key_array);

    } else {
        println!("No valid key found!\n");
        return Ok(());
    }

    let matching_key_array = matching_key.as_ref().unwrap();

    let mut hdr_reader = Cursor::new(header);
    let mut modules: Vec<ModuleEntry> = Vec::new();

    for i in 0..100 {
        let entry: ModuleEntry = hdr_reader.read_le()?;
        if !entry.is_valid() {break};
        println!("Module {} - Name: {}, Version: {}, Platform: {}, ID: {}, Offset: {}, Size: {}",
                i + 1, entry.name(), entry.version(), entry.platform(), entry.id(), entry.offset, entry.size);
        if modules.iter().any(|m| m.name() == entry.name()){
            println!("- Duplicate module, skipping!");
            continue
        }
        modules.push(entry);
    }

    let mut main_offset: Option<u32> = None;
    for module in modules {
        println!("\nSave module {}, Offset: {}, Size: {}, Expected checksum: {:#010x}",
                module.name(), module.offset, module.size, module.data_checksum);

        file_reader.seek(SeekFrom::Start(module.offset as u64))?;
        let data = common::read_exact(&mut file_reader, module.size as usize)?;
        let checksum = adler32(&data.as_slice());

        if module.name() == "MAIN" {
            if checksum == module.data_checksum {
                main_offset = Some(module.offset);
                println!("- Valid MAIN data found - will extract later...");
                continue
            } else {
                println!("- WARNING: Invalid/unsupported MAIN data!")
            } 
        }

        println!("- Decrypting...");
        let dec_data = decrypt_data(&data, &matching_key_array);

        let output_path = Path::new(&output_folder).join(format!("{}.bin", module.name()));

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&dec_data)?;
        
        println!("-- Saved file!");
  
    }

    if !main_offset.is_some() {
        println!("\nExtraction finished!");
        return Ok(())
    }
    println!("\nExtracting MAIN section...");

    let main_offset_unwrap = main_offset.unwrap();
    file_reader.seek(SeekFrom::Start(main_offset_unwrap as u64))?;

    let main_list_hdr: MainListHeader = file_reader.read_le()?;
    println!("MAIN entry count: {}", main_list_hdr.entry_count());

    let mut main_entries: Vec<MainListEntry> = Vec::new();
    for i in 0..main_list_hdr.entry_count() {
        let main_entry: MainListEntry = file_reader.read_le()?;
        println!("- Entry {}/{} - Size: {}, Checksum: {:#010x}",
                i + 1, main_list_hdr.entry_count(), main_entry.size, main_entry.checksum);
        main_entries.push(main_entry);
    }

    for entry in main_entries {
        let mut data = common::read_exact(&mut file_reader, entry.size as usize)?;
        if entry.size > 5120 {
            //decrypt first and last 5kb
            let first_decrypted = decrypt_data(&data[..5120], &matching_key_array);
            data[..5120].copy_from_slice(&first_decrypted);

            let last_decrypted = decrypt_data(&data[entry.size as usize - 5120..], &matching_key_array);
            data[entry.size as usize - 5120..].copy_from_slice(&last_decrypted);
            //
        } else {
            let decrypted = decrypt_data(&data, &matching_key_array);
            data.copy_from_slice(&decrypted);
        }
        

        let mut data_reader = Cursor::new(data);
        let header: MainEntryHeader = data_reader.read_le()?;
        println!("\nSaving entry - Compressed size: {}, Decompressed size: {}, Compression type: {}({})", 
                header.compressed_size, header.decompressed_size, header.compression_type_byte, header.compression_type());
        let compressed_data = common::read_exact(&mut data_reader, header.compressed_size as usize)?;

        let decompressed_data;
        if header.compression_type_byte == 1 { //gzip + lzss
            println!("- (1/2) Decompressing GZIP...");
            let decompressed_gzip = decompress_gzip(&compressed_data)?;
            // the decompressed data has another header
            let mut decompressed_gzip_reader = Cursor::new(decompressed_gzip);
            let header: MainEntryHeader = decompressed_gzip_reader.read_le()?;
            println!("- (2/2) Decompressing LZSS... (Compressed size: {}, Decompressed size: {})", header.compressed_size, header.decompressed_size);
            let compressed_lzss = common::read_exact(&mut decompressed_gzip_reader, header.compressed_size as usize)?;
            decompressed_data = decompress_lzss(&compressed_lzss);
            assert!(decompressed_data.len() == header.decompressed_size as usize, "Decompressed size does not match size in header, decompression failed!");
        } else if header.compression_type_byte == 2 { //only lzss
            println!("- Decompressing LZSS...");
            decompressed_data = decompress_lzss(&compressed_data);
            assert!(decompressed_data.len() == header.decompressed_size as usize, "Decompressed size does not match size in header, decompression failed!");
        } else if header.compression_type_byte == 0 { //no compression. havent encountered one yet
            decompressed_data = compressed_data;
        } else {
            println!("- Unknown compression method!");
            decompressed_data = compressed_data;
        }

        let output_path = Path::new(&output_folder).join("MAIN.bin");

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
        out_file.write_all(&decompressed_data)?;
        
        println!("- Saved to MAIN!");
    }

    println!("\nExtraction finished!");
    Ok(())
}
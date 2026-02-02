use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::utils::lzhs::{decompress_lzhs_fs_file2file};
use crate::keys;

use crate::formats::mtk_pkg::{MTK_HEADER_MAGIC, MTK_META_MAGIC, MTK_META_PAD_MAGIC};

pub struct MtkPkgNewContext {
    matching_key_name: String,
    matching_key_key: [u8; 16],
    matching_key_iv: [u8; 16],
    decrypted_header: Vec<u8>,
}

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] vendor_magic_bytes: Vec<u8>,
    #[br(count = 8)] _mtk_magic: Vec<u8>, //#DH@FiRm
	#[br(count = 56)] version_bytes: Vec<u8>,
    _unk: u32,
	file_size: u32,
    _flags: u32,
    #[br(count = 32)] product_name_bytes: Vec<u8>,
    #[br(count = 256)] _digest: Vec<u8>,
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
        (self.flags & 1 << 0) != 0
    }
    fn is_compressed(&self) -> bool { //lzhs fs
        (self.flags & 1 << 8) != 0
    }
}

static HEADER_SIZE: usize = 0x170;

pub fn is_mtk_pkg_new_file(file: &File) -> Result<Option<MtkPkgNewContext>, Box<dyn std::error::Error>> {
    let encrypted_header = common::read_file(&file, 0, HEADER_SIZE)?;
    for (key_hex, iv_hex, name) in keys::MTK_PKG_CUST {
        let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
        let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
        let try_decrypt = decrypt_aes128_cbc_nopad(&encrypted_header, &key_array, &iv_array)?;

        if &try_decrypt[4..12] == MTK_HEADER_MAGIC {    
            return Ok(Some(MtkPkgNewContext {
                matching_key_name: name.to_string(),
                matching_key_key: key_array,
                matching_key_iv: iv_array,
                decrypted_header: try_decrypt
            }));
        }
    }

    Ok(None)
}

pub fn extract_mtk_pkg_new(mut file: &File, output_folder: &str, context: MtkPkgNewContext) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();

    //the key was founf, and header was decrypted at detection stage so we can reuse
    println!("Using key {}", context.matching_key_name);
    let key_array = context.matching_key_key;
    let iv_array = context.matching_key_iv;
    let header = context.decrypted_header;

    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {        
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        if !part_entry.is_valid() {
            break
        }

        println!("\n#{} - {}, Size: {}{} {}", 
                part_n, part_entry.name(), part_entry.size, if part_entry.is_compressed() {" [COMPRESSED]"} else {""}, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize + 48)?;
        
        if part_entry.size == 0 {
            println!("- Empty entry, skipping!");
            continue
        }

        let mut out_data;
        if part_entry.is_encrypted() {
            println!("- Decrypting...");
            //data aligned to 16 bytes is AES encrypted. the remaining unaligned data is XORed with the key
            let align_len = data.len() & !15;
            let (aes_enc, xor_tail) = data.split_at(align_len);
            out_data = decrypt_aes128_cbc_nopad(aes_enc, &key_array, &iv_array)?;
            for (i, &b) in xor_tail.iter().enumerate() {
                out_data.push(b ^ key_array[i % key_array.len()]);
            }
        } else {
            out_data = data;
        }

        //strip iMtK thing and get version
        let extra_header_len = if &out_data[48..52] == MTK_META_MAGIC {
            let imtk_len = u32::from_le_bytes(out_data[52..56].try_into().unwrap());
            if &out_data[56..60] != MTK_META_PAD_MAGIC {
                let version_len = u32::from_le_bytes(out_data[56..60].try_into().unwrap());
                let version = common::string_from_bytes(&out_data[60..60 + version_len as usize]);
                println!("- Version: {}", version);
            }
            imtk_len + 8
        } else {
            0
        };
        
        //for compressed part create temp file
        let output_path = Path::new(&output_folder).join(part_entry.name() + if part_entry.is_compressed() {".lzhs"} else {".bin"});
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new().write(true).read(true)/* for lzhs */.create(true).open(&output_path)?;
        out_file.write_all(&out_data[48 + extra_header_len as usize..])?;

        if part_entry.is_compressed() {
            let lzhs_out_path = Path::new(&output_folder).join(part_entry.name() + ".bin");
            match decompress_lzhs_fs_file2file(&out_file, lzhs_out_path) {
                Ok(()) => {
                    println!("-- Decompressed Successfully!");
                    //after successfull decompression remove the temporary .lzhs file
                    fs::remove_file(&output_path)?;
                },
                Err(e) => {
                    eprintln!("Failed to decompress partition!, Error: {}. Saving compressed data...", e);
                    //if the decompression is not successfull leave out compressed data.
                }
            }   
        }

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
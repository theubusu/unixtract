use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::aes::{decrypt_aes128_cbc_nopad};
use crate::utils::lzhs::{decompress_lzhs_fs_file2file};
use crate::keys;

pub struct MtkPkgContext {
    is_philips_variant: bool,
    decrypted_header: Vec<u8>,
}

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] vendor_magic_bytes: Vec<u8>,
    #[br(count = 8)] _mtk_magic: Vec<u8>, //#DH@FiRm
	#[br(count = 60)] version_bytes: Vec<u8>,
	file_size: u32,
    _flags: u32,
    #[br(count = 32)] product_name_bytes: Vec<u8>,
    #[br(count = 32)] _digest: Vec<u8>,
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

pub static MTK_HEADER_MAGIC: &[u8; 8] = b"#DH@FiRm";
pub static MTK_RESERVED_MAGIC: &[u8; 16] = b"reserved mtk inc";
pub static MTK_META_MAGIC: &[u8; 4] = b"iMtK";
pub static MTK_META_PAD_MAGIC: &[u8; 4] = b"iPAd";
pub static CRYPTED_HEADER_SIZE: usize = 0x30;

static HEADER_SIZE: usize = 0x90;

static PHILIPS_EXTRA_HEADER_SIZE: usize = 0x80;
static _PHILIPS_FOOTER_SIGNATURE_SIZE: usize = 0x100;

static HEADER_KEY: [u8; 16] = [
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
        0x09, 0x29, 0x10, 0x94, 0x09, 0x29, 0x10, 0x94,
];

static HEADER_IV: [u8; 16] = [0x00; 16];

pub fn is_mtk_pkg_file(file: &File) -> Result<Option<MtkPkgContext>, Box<dyn std::error::Error>> {
    let mut encrypted_header = common::read_file(&file, 0, HEADER_SIZE)?;
    let mut header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV)?;
    if &header[4..12] == MTK_HEADER_MAGIC {
        Ok(Some(MtkPkgContext { is_philips_variant: false, decrypted_header: header}))
    } else {
        // try for philips which has additional 128 bytes at beginning
        encrypted_header = common::read_file(&file, PHILIPS_EXTRA_HEADER_SIZE as u64, HEADER_SIZE)?;
        header = decrypt_aes128_cbc_nopad(&encrypted_header, &HEADER_KEY, &HEADER_IV)?;
        if &header[4..12] == MTK_HEADER_MAGIC {
            Ok(Some(MtkPkgContext { is_philips_variant: true, decrypted_header: header }))
        } else {
            Ok(None)

        }
    }
}

pub fn extract_mtk_pkg(mut file: &File, output_folder: &str, context: MtkPkgContext) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();
    let header = context.decrypted_header;
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    if context.is_philips_variant {
        file.seek(SeekFrom::Start(HEADER_SIZE as u64 + PHILIPS_EXTRA_HEADER_SIZE as u64))?;
    } else {
        file.seek(SeekFrom::Start(HEADER_SIZE as u64))?;
    }

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {        
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        if !part_entry.is_valid() {break};

        println!("\n#{} - {}, Size: {}{} {}", 
                part_n, part_entry.name(), part_entry.size, if part_entry.is_compressed() {" [COMPRESSED]"} else {""}, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize + CRYPTED_HEADER_SIZE)?;
        
        if part_entry.size == 0 {
            println!("- Empty entry, skipping!");
            continue
        }

        let mut out_data;
        if part_entry.is_encrypted() {
            let mut matching_key: Option<[u8; 16]> = None;
            let mut matching_iv: Option<[u8; 16]> = None;

            let crypted_header = &data[..CRYPTED_HEADER_SIZE];

            // try decrypting with vendor magic repeated 4 times (works for most)
            let mut key = [0u8; 16];
            for i in 0..4 {
                key[i * 4..(i + 1) * 4].copy_from_slice(&hdr.vendor_magic_bytes);
            }
            let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key, &HEADER_IV)?;
            if try_decrypt.starts_with(MTK_RESERVED_MAGIC) {
                println!("- Decrypting with 4xVendor magic...");
                matching_key = Some(key);
                matching_iv = Some(HEADER_IV);

            } else {
                //try decrypting with one of custom keys
                for (key_hex, iv_hex, name) in keys::MTK_PKG_CUST {
                    let key_array: [u8; 16] = hex::decode(key_hex)?.as_slice().try_into()?;
                    let iv_array: [u8; 16] = hex::decode(iv_hex)?.as_slice().try_into()?;
                    let try_decrypt = decrypt_aes128_cbc_nopad(&crypted_header, &key_array, &iv_array)?;

                    if try_decrypt.starts_with(MTK_RESERVED_MAGIC) {
                        println!("- Decrypting with key {}...", name);
                        matching_key = Some(key_array);
                        matching_iv = Some(iv_array);
                        break
                    }
                }
            }

            if matching_key.is_some() && matching_iv.is_some() {
                let (key_array, iv_array) = (matching_key.unwrap(), matching_iv.unwrap());
                //data aligned to 16 bytes is AES encrypted. the remaining unaligned data is XORed with the key
                let align_len = data.len() & !15;
                let (aes_enc, xor_tail) = data.split_at(align_len);
                out_data = decrypt_aes128_cbc_nopad(aes_enc, &key_array, &iv_array)?;
                for (i, &b) in xor_tail.iter().enumerate() {
                    out_data.push(b ^ key_array[i % key_array.len()]);
                }
            } else {
                println!("- Failed to decrypt data!");
                continue
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
        out_file.write_all(&out_data[CRYPTED_HEADER_SIZE + extra_header_len as usize..])?;

        if part_entry.is_compressed() {
            let lzhs_out_path = Path::new(&output_folder).join(part_entry.name() + ".bin");
            match decompress_lzhs_fs_file2file(&out_file, lzhs_out_path) {
                Ok(()) => {
                    println!("- Decompressed Successfully!");
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
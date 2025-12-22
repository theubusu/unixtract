use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Cursor, Seek};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;
use crate::utils::mtk_crypto::{decrypt};

static KEY: u32 = 0x94102909; //09 29 10 94
// first 4 bytes of header and content are additionally XORed, they have different masks although only differ by half a byte
static HEADER_XOR_MASK: u32 = 0x04BE7C75; //75 7C BE 04
static CONTENT_XOR_MASK: u32 = 0x04BE7C72; //72 7C BE 04

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] vendor_magic_bytes: Vec<u8>,
    #[br(count = 8)] _mtk_magic: Vec<u8>, //#DH@FiRm
	#[br(count = 68)] version_bytes: Vec<u8>,
	file_size: u32,
    _flags: u32,
    #[br(count = 32)] product_name_bytes: Vec<u8>,
    #[br(count = 32)] _encrypted_digest: Vec<u8>,
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
    fn is_encrypted(&self) -> bool {
        (self.flags & 1 << 0) == 1 << 0
    }
}

pub fn is_mtk_pkg_old_file(mut file: &File) -> bool {
    let encrypted_header = common::read_file(&file, 0, 152).expect("Failed to read from file.");
    let header = decrypt(&encrypted_header, KEY, Some(HEADER_XOR_MASK));
    if &header[4..12] == b"#DH@FiRm" {
        true
    } else if &header[68..76] == b"#DH@FiRm" {
        //check for 64 byte additional header used in some Sony and Philips firmwares and skip it
        file.seek(std::io::SeekFrom::Start(64)).expect("Failed to seek");
        true
    } else if &header[132..140] == b"#DH@FiRm" {
        //check for 128 byte additional header used in some Philips firmwares and skip it
        file.seek(std::io::SeekFrom::Start(128)).expect("Failed to seek");
        true
    } else {
        false
    }
}

pub fn extract_mtk_pkg_old(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();
    let encrypted_header = common::read_exact(&mut file, 152)?;
    let header = decrypt(&encrypted_header, KEY, Some(HEADER_XOR_MASK));
    let mut hdr_reader = Cursor::new(header); 
    let hdr: Header = hdr_reader.read_le()?;

    println!("File info:\nFile size: {}\nVendor magic: {}\nVersion info: {}\nProduct name: {}" , 
            hdr.file_size, hdr.vendor_magic(), hdr.version(), hdr.product_name());

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;

        println!("\n#{} - {}, Size: {} {}", part_n, part_entry.name(), part_entry.size, if part_entry.is_encrypted() {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize)?;
        let out_data; 
        if part_entry.is_encrypted() {
            //decrypt with the vendor magic
            println!("- Decrypting...");
            let vendor_magic_u32 = u32::from_le_bytes(hdr.vendor_magic_bytes.clone().try_into().unwrap());
            out_data = decrypt(&data, vendor_magic_u32, Some(CONTENT_XOR_MASK));
        } else {
            out_data = data;
        }

        //strip iMtK thing and get version
        let extra_header_len = if &out_data[0..4] == b"iMtK" {
            let imtk_len = u32::from_le_bytes(out_data[4..8].try_into().unwrap());
            if &out_data[8..12] != b"iPAd" {
                let version_len = u32::from_le_bytes(out_data[8..12].try_into().unwrap());
                let version = common::string_from_bytes(&out_data[12..12 + version_len as usize]);
                println!("- Version: {}", version);
            }
            imtk_len + 8
        } else {
            0
        };

        let output_path = Path::new(&output_folder).join(part_entry.name() + ".bin");
        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;
        out_file.write_all(&out_data[extra_header_len as usize..])?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Seek};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

pub fn is_mtk_upgrade_loader_file(file: &File) -> bool {
    let header = common::read_file(&file, 152, 4).expect("Failed to read from file.");
    if header == b"cfig" || header == b"load" { //cfig or load is always(?) the first partition in upgrade_loader
        true
    } else {
        false
    }
}

//This format is similar to mtk_pkg, but has different header size and key. It also doesnt have the crypted headers

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
}

pub fn extract_mtk_upgrade_loader(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_size = file.metadata()?.len();

    let mut part_n = 0;
    while file.stream_position()? < file_size as u64 {
        part_n += 1;
        let part_entry: PartEntry = file.read_le()?;
        let is_encrypted = if (part_entry.flags & 1 << 0) == 1 << 0 {true} else {false};

        println!("\n{} - {}, Size: {} {}", part_n, part_entry.name(), part_entry.size, if is_encrypted {"[ENCRYPTED]"} else {""} );

        let data = common::read_exact(&mut file, part_entry.size as usize)?;

        //strip iMtK thing
        let extra_header_len = if &data[0..4] == b"iMtK" {
            let imtk_len = u32::from_le_bytes(data[4..8].try_into().unwrap());
            imtk_len + 8
        } else {
            0
        };

        //println!("Extra header size: {}", extra_header_len);

        let output_path = Path::new(&output_folder).join(part_entry.name() + ".bin");

        fs::create_dir_all(&output_folder)?;
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(output_path)?;

        out_file.write_all(&data[extra_header_len as usize..])?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
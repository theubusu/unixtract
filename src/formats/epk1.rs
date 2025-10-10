use std::fs::File;
use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};

use binrw::{BinRead, BinReaderExt};

use crate::common;

#[derive(BinRead)]
struct CommonHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>,
    file_size: u32,
    pak_count: u32,
}

#[derive(BinRead)]
struct Pak {
    offset : u32,
    size : u32,
}

#[derive(BinRead)]
struct PakHeader {
    #[br(count = 4)] pak_name_bytes: Vec<u8>,
    stored_size: u32,
	#[br(count = 15)] platform_id_bytes: Vec<u8>,
}
impl PakHeader {
    fn pak_name(&self) -> String {
        common::string_from_bytes(&self.pak_name_bytes)
    }
    fn platform_id(&self) -> String {
        common::string_from_bytes(&self.platform_id_bytes)
    }
}

pub fn is_epk1_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 4).expect("Failed to read from file.");
    if header == b"epak" {
        true
    } else {
        false
    }
}

pub fn extract_epk1(mut file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {
    //check type of epk1
    let epk1_type;
    let init_pak_count_bytes = common::read_file(&file, 8, 4)?;
    let init_pak_count = u32::from_le_bytes(init_pak_count_bytes.try_into().unwrap());

    if init_pak_count > 256 {
        println!("\nBig endian EPK1 detected.");
        epk1_type = "be";
    } else if init_pak_count < 21 {
        println!("\nLittle endian EPK1 detected.");
        epk1_type = "le";
    } else {
        //println!("\nEPK1(new) detected.");
        //epk1_type = "new";
        println!("\nNot supported!");
        return Ok(());
    }

    file.seek(SeekFrom::Start(0))?;

    let mut paks: Vec<Pak> = Vec::new();

    if epk1_type == "be" {
        let header: CommonHeader = file.read_be()?;

        for _i in 0..10 { //header can fit max 10 pak entries
            let pak: Pak = file.read_be()?;

            if pak.offset == 0 && pak.size == 0 {
                continue;
            }

            paks.push(Pak { offset: pak.offset, size: pak.size });
        }

        assert!(header.pak_count as usize == paks.len(), "Paks count in header does not match the amount of non empty pak entries!");

        let version = common::read_exact(&mut file, 4)?;

        println!("EPK info:\nFile size: {}\nPak count: {}\nVersion: {:02x?}.{:02x?}.{:02x?}",
                header.file_size, header.pak_count, version[1], version[2], version[3]);

    } else if epk1_type == "le" {
        let header: CommonHeader = file.read_le()?;

        for _i in 0..20 { //header can fit max 20 pak entries
            let pak: Pak = file.read_le()?;

            if pak.offset == 0 && pak.size == 0 {
                continue;
            }

            paks.push(Pak { offset: pak.offset, size: pak.size });
        }

        assert!(header.pak_count as usize == paks.len(), "Paks count in header does not match the amount of non empty pak entries!");

        let version = common::read_exact(&mut file, 4)?;

        let ota_id_bytes = common::read_exact(&mut file, 32)?;
        let ota_id = common::string_from_bytes(&ota_id_bytes);

        println!("EPK info:\nFile size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}", 
                header.file_size, header.pak_count, ota_id, version[2], version[1], version[0]);
    }

    for (i, pak) in paks.iter().enumerate() {
            file.seek(SeekFrom::Start(pak.offset as u64))?;
            let pak_header: PakHeader = if epk1_type == "be" {file.read_be()?} else {file.read_le()?};

            let data = common::read_file(&file, pak.offset as u64 + 128, pak.size as usize - 128)?;

            println!("\nPak {}: {}, Offset: {}, Size: {}, Platform: {}", i + 1, pak_header.pak_name(), pak.offset, pak.size, pak_header.platform_id());

            let output_path = Path::new(&output_folder).join(pak_header.pak_name() + ".bin");

            fs::create_dir_all(&output_folder)?;
            let mut out_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(output_path)?;
            
            out_file.write_all(&data[..pak_header.stored_size as usize])?;

            println!("- Saved file!");
        }
    
    println!("\nExtraction finished!");

    Ok(())
}
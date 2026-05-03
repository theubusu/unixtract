mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Read, Cursor, Seek};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub struct RvpContext {
    header_type: HeaderType,
}

pub fn is_rvp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    //MVP
    let header = common::read_file(&file, 0, 4)?;
    if header == b"UPDT" {
        return Ok(Some(Box::new(RvpContext {header_type: HeaderType::MVP})))
    }

    //RVP
    let bytes = common::read_file(&file, 16, 18)?;
    for (_i, &b) in bytes.iter().enumerate().step_by(2) {
        if b != 0xA3 {
            return Ok(None);
        }
    }
    
    Ok(Some(Box::new(RvpContext {header_type: HeaderType::RVP})))
}

pub fn extract_rvp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<RvpContext>().expect("Missing context");

    if ctx.header_type == HeaderType::RVP {
        let header: RVPHeader = file.read_be()?;
        println!("RVP Info -\nVersion: {}\nYear: {:x}\nForce: {}", header.version_info(), header.year, header.force);

    } else if ctx.header_type == HeaderType::MVP {
        file.seek(std::io::SeekFrom::Start(36))?;
    }

    let mut obf_data = Vec::new();
    file.read_to_end(&mut obf_data)?;
    println!("DeXORing data..");

    let data = decrypt_xor(&obf_data); 
    let data_size = data.len();
    let mut data_reader = Cursor::new(data);

    let module_count: u32 = data_reader.read_le()?;    //little endian??
    println!("Module count: {}", module_count);

    //follows table of sizes of modules, structure is static for given module
    let mut module_names: Vec<&str> = Vec::new();
    for i in 0..63 {
        if i >= KNOWN_MODULES.len() {
            break
        }
        let module_size: u32 = data_reader.read_be()?;
        if module_size == 0 {
            continue
        }
        if module_size as usize > data_size {
            break
        }
        module_names.push(KNOWN_MODULES[i]);
    }

    data_reader.seek(std::io::SeekFrom::Start(256))?;

    for i in 0..module_count as usize {
        let module_name = if i >= module_names.len() {
            "unknown"
        } else {
            module_names[i]
        };

        let header_size_bytes = common::read_exact(&mut data_reader, 4)?;
        let header_size = u32::from_be_bytes(header_size_bytes.try_into().unwrap());
        println!("\n({}/{}) - {}, Offset: {}, Header size: {}", i+1, module_count, module_name, data_reader.position() - 4, header_size);
        let hdr = common::read_exact(&mut data_reader, header_size as usize)?;

        let size;
        let mut name = String::new();
        if i == 0 { //first entry is always HOST module (SEINE)
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();

            //BEAUTIFUL
            println!("ModelName: {}\nFileName: {}\nModelID: {}\nNewUpdate: {}\nNewMajorVer: {}\nNewMinorVer: {}\nForcedFlag: {}\nStartAddress: {}\nJumpAddress: {}\nMagicAddress: {}\nTotalSize: {}\nTotalSum: {}\nTotalCrc: {}",
                    lines[0], lines[1], lines[2], lines[3], lines[4], lines[5], lines[6], lines[7], lines[8], lines[9], lines[10], lines[11], lines[12]);

            size = lines[10].parse().unwrap();

        } else if header_size == 32 {
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();
            //1. CRC32 checksum like "34D0757C"
            //2. unknown - "FFFFFFFF"
            //3. size in hex string like "00040000"
            size = u32::from_str_radix(&lines[2], 16).unwrap();

        } else if header_size == 48 || header_size == 44 || header_size == 40 {     //for disk drive firmware 
            let hdr_string = String::from_utf8_lossy(&hdr);
            let lines: Vec<String> = hdr_string.lines().map(|l| l.trim().to_string()).collect();
            //1. - name, like "L12_110.IMG"
            //2. - size in hex string like "001E6388"
            //3. - unknown - single number like "3" (force flag?)
            //4. - crc32 checksum like "0BC0F6F7"
            //5. - unknown - like "00011200" -- this line is not present when size is 40 but were not using it anyway so whatever
            name = lines[0].clone();
            size = u32::from_str_radix(&lines[1], 16).unwrap();
            println!("Name: {}", name);

        } else if header_size == 16 {
            // 4 bytes CRC32
            // 4 bytes unknown "FF FF FF FF"
            // 4 bytes size
            // 4 bytes unknown "00 00 00 00"
            size = u32::from_be_bytes(hdr[8..12].try_into().unwrap());

        } else {
            println!("Unsupported header size!");
            break
        }

        println!("Size: {}", size);
        let data = common::read_exact(&mut data_reader, size as usize)?;
        let output_path = Path::new(&app_ctx.output_dir).join(if name=="" {format!("{}_{}.bin", i+1, module_name)} else {format!("{}_{}_{}", i+1, module_name, name)});

        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;      
        out_file.write_all(&data)?;

        println!("- Saved file!");
    }

    Ok(())
}
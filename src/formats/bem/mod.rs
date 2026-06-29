mod include;
use std::any::Any;
use crate::AppContext;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;
use crate::formats::msd::decrypt_aes_tizen;

struct BemCtx {
    format_version: BemFormatVersion,
}

pub fn is_bem_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header_magic = common::read_file(&file, 0, 6)?;
    if header_magic.starts_with(b"BEMU") {
        if header_magic == b"BEMU20" {
            Ok(Some(Box::new(BemCtx {format_version: BemFormatVersion::Bem20})))
        } else if header_magic == b"BEMU10" {
            Ok(Some(Box::new(BemCtx {format_version: BemFormatVersion::Bem10})))
        } else {
            Ok(None)    //?
        }
    } else {
        Ok(None)
    }
}

pub fn extract_bem(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<BemCtx>().expect("Missing context");

    let bem_header: Box<dyn CSWUpgradeFileHeader> = match ctx.format_version {
        BemFormatVersion::Bem10 => Box::new(file.read_le::<CSWUpgradeFileHeader10>()?),
        BemFormatVersion::Bem20 => Box::new(file.read_le::<CSWUpgradeFileHeader20>()?),
    };

    //read encrypted version block
    let encrypted_data = common::read_exact(&mut file, bem_header.encrypted_data_lenght() as usize)?;
    let _signature = common::read_exact(&mut file, bem_header.signature_lenght() as usize)?;

    //find passphrase
    let mut passphrase_bytes: Option<&Vec<u8>> = None;
    let mut passphrase_name: &str = "";
    let mut decrypted_data: Vec<u8> = vec![];
    for (name, keys) in app_ctx.keys.get_collection("MSD11")? {
        let passphrase = keys.first().unwrap();
        match decrypt_aes_tizen(&encrypted_data, &passphrase, &bem_header.salt()) {
            Ok(result) => {
                if result.len() == bem_header.original_data_lenght() as usize { //verify padding was correct
                    passphrase_bytes = Some(passphrase);
                    passphrase_name = name;
                    decrypted_data = result;
                    break
                } else {
                    continue
                }
            },
            Err(_) => continue,
        };
    }
    
    let passphrase_bytes = if let Some(p) = passphrase_bytes {
        println!("Using passphrase: {}", passphrase_name);
        p
    } else {
        return Err("No matching key found!".into());
    };

    //parse decrypted version
    let version_len = u32::from_le_bytes(decrypted_data[..4].try_into().unwrap()) as usize;
    let version = common::string_from_bytes(&decrypted_data[4..4+version_len]);

    println!("Version: {}", version);

    let file_size = file.metadata()?.len();

    let mut e_i = 0;
    while file.stream_position()? < file_size {
        let mut block_header: CSWUpgradeDataBlock = file.read_le()?;

        println!("\n#{} - {}, Block count: {}", e_i+1, block_header.image_name(), block_header.total_blocks);

        let output_path = Path::new(&app_ctx.output_dir).join(block_header.image_name());
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;

        for i in 0..block_header.total_blocks {
            // for first block we already read the header so skip doing that for it
            if i > 0 {
                block_header = file.read_le()?;
            }

            if block_header.block_number != i+1 {
                return Err("unexpected block number in block".into());
            }

            println!("- Block {}/{} - Size: {}", 
                    block_header.block_number, block_header.total_blocks, block_header.original_data_lenght);

            let encrypted_data = common::read_exact(&mut file, block_header.encrypted_data_lenght as usize)?;
            let _signature = common::read_exact(&mut file, block_header.signature_lenght as usize)?;

            let decrypted_data = decrypt_aes_tizen(&encrypted_data, &passphrase_bytes, &bem_header.salt())?;
            out_file.write_all(&decrypted_data)?;

            println!("-- Saved to file!");
        }

        e_i += 1;
    }
    
    Ok(())
}
use std::any::Any;
use crate::{AppContext, formats::Format};
pub fn format() -> Format {
    Format { name: "android_ota_payload", detector_func: is_android_ota_payload_file, extractor_func: extract_android_ota_payload }
}

use std::fs::{self, OpenOptions};
use std::path::{Path};
use std::io::{Write};
use binrw::{BinRead, BinReaderExt};
use prost::Message;

use crate::utils::common;
use crate::utils::android_ota_update_metadata::{DeltaArchiveManifest, install_operation};
use crate::utils::compression::{decompress_bzip, decompress_xz};

#[derive(BinRead)]
struct Header {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //CrAU
    file_format_version: u64,
    manifest_size: u64,
    metadata_signature_size: u32,
}

pub fn is_android_ota_payload_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let header = common::read_file(app_ctx.file, 0, 4)?;
    if header == b"CrAU" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_android_ota_payload(app_ctx: &AppContext, _ctx: Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file;
    let header: Header = file.read_be()?;
    println!("File info:\nFormat version: {}\nManifest size: {}", header.file_format_version, header.manifest_size);

    if header.file_format_version != 2 {
        println!("\nSorry, this version of the file is not supported!");
        return Ok(())
    }

    let base_offset = 24 /* size of header */ + header.manifest_size + header.metadata_signature_size as u64;

    let read_manifest = common::read_exact(&mut file, header.manifest_size as usize)?;
    let manifest = DeltaArchiveManifest::decode(&*read_manifest)?;

    for (i, partition) in manifest.partitions.into_iter().enumerate() {
        let operation_count = partition.operations.len();
        println!("\n#{} - {}, Size: {}, Operations: {}", 
                i + 1, partition.partition_name, partition.new_partition_info.unwrap().size.unwrap(), operation_count);
        
        for (i, operation) in partition.operations.into_iter().enumerate() {
            let operation_name_str = match install_operation::Type::try_from(operation.r#type) {
                Ok(t) => t.as_str_name(),
                Err(_) => "UNKNOWN",
            };

            let offset = base_offset + operation.data_offset.unwrap();
            let size = operation.data_length.unwrap();

            //because the amount of operations can reach up to the thousands, i think its best to update the current line
            //to not clog up the terminal and so you know what the program is actually doing
            print!("\r- ({}/{}) - {}({}), Offset: {}, Size: {}", 
                    i + 1, operation_count, operation_name_str, operation.r#type, offset, size);
            std::io::stdout().flush()?;

            let data = common::read_file(&file, offset, size as usize)?;

            let out_data;
            if operation.r#type == 0 { //REPLACE - just write the stored data
                out_data = data;
            }
            else if operation.r#type == 1 { //REPLACE_BZ - decompress with bzip and write
                out_data = decompress_bzip(&data)?;
            }
            else if operation.r#type == 8 { //REPLACE_XZ - decompress with xz and write
                out_data = decompress_xz(&data)?;
            } else {
                println!("-- Unsupported operation!");
                break
            }

            fs::create_dir_all(app_ctx.output_dir)?;
            let output_path = Path::new(app_ctx.output_dir).join(format!("{}.bin", partition.partition_name));
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data)?;
        }
        println!("\n-- Saved!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
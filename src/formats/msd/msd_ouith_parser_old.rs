//MAIN CODE: https://github.com/theubusu/msd_OUITH_parser

use std::io::{Seek, SeekFrom, Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

// whether to print the tree
static CONFIG_PRINT_TREE: bool = false;

#[derive(BinRead)]
struct ChunkHeader {
    size: u32,
    value: u32,
}

#[derive(BinRead)]
struct DescriptorHeader {
    tag: u16,
    size: u32,
}

#[derive(BinRead)]
//OUSWFileVersionDesc, OUPartitionVersionDesc, OUCMACDataDesc
struct CommonDestinationInfo {
    name_len: u8,
    #[br(count = name_len)] name_bytes: Vec<u8>,
    version: u16,
}
impl CommonDestinationInfo {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct OUAESEncryptionDesc {
    mode: u8,
    key_size: u32,
    salt_size: u32,
}

#[derive(BinRead)]
struct OURSAValidationDesc {
    mode: u8,
    _unknown: u32,
    signature_size: u32,
}

#[derive(BinRead)]
struct OUSecureHashValidationDesc {
    mode: u8,
    hash_size: u16,
    #[br(count = hash_size)] hash: Vec<u8>,
}

#[derive(BinRead)]
struct OUGroupDesc {
    group_id: u32,
    field_2: u8,
    field_3: u8,
}

#[derive(BinRead)]
pub struct OUSWImageVersionExDesc {
    pub name_len: u8,
    #[br(count = name_len)] pub name_bytes: Vec<u8>,
    pub major_ver: u16,
    pub minor_ver: u16,
    pub date_year: u8,
    pub date_month: u8,
    pub date_day: u8,
}
impl OUSWImageVersionExDesc {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

//this is a struct that will communicate all values important when parsing the MSD file.
pub struct MSDItem {
    pub item_id: u32,
    pub item_type: u16, //File, Partition, CMACData
    pub all_size: u32, //same size as in msd header
    pub name: String,

    pub heading_size: u32, //has the signature and salt
    pub data_size: u32,

    pub aes_encryption: bool,
    //pub crc32_hash: Option<u32>,
    //pub secure_hash: Option<Vec<u8>>,
}

pub fn parse_ouith_blob(blob: &[u8]) -> Result<(Vec<MSDItem>, Option<OUSWImageVersionExDesc>), Box<dyn std::error::Error>> {
    let mut reader = Cursor::new(blob);
    let mut items: Vec<MSDItem> = Vec::new();
    let mut info: Option<OUSWImageVersionExDesc> = None;

    let _signature = common::read_exact(&mut reader, 128)?; //signature included at the beginning of blob in MSD file
    
    let mut chunk_n = 0;
    while reader.stream_position()? < blob.len() as u64 {
        chunk_n += 1;
        let chunk: ChunkHeader = reader.read_be()?;
        if CONFIG_PRINT_TREE { println!("\nChunk {} - Size: {}, Value: {}", chunk_n, chunk.size, chunk.value); };
        let chunk_end = reader.stream_position()? + chunk.size as u64;

        //parse top level descriptor. it can only be ID 1(OUUpgradeItemDesc) or 2(OUGroupDesc)
        let top_descriptor: DescriptorHeader = reader.read_be()?;
        if top_descriptor.tag == 0x01 {
            if CONFIG_PRINT_TREE { println!("OUUpgradeItemDesc(0x01) - Size: {}", top_descriptor.size); };

            let item_id: u32 = reader.read_be()?;
            if CONFIG_PRINT_TREE { println!("  Item ID: {}", item_id); };

            //REQUIRED are items in order: OUDestinationDesc(0x03), OUDataProcessingDesc(0x07), OUGroupInfoDesc(0x13). OPTIONAL items: OUDependenciesDesc(0x04), OUDataPostProcessingDesc(0x08)
            //In MSD files, no others seem to be used than the required ones. We will ignore all data after required descriptors.
            let destination_descriptor: DescriptorHeader = reader.read_be()?;
            if destination_descriptor.tag != 0x03 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x03, Got: 0x{:02x}!", destination_descriptor.tag).into())}
            if CONFIG_PRINT_TREE { println!("  OUDestinationDesc(0x03) - Size: {}", destination_descriptor.size); };
            let out_size: u32 = reader.read_be()?;
            if CONFIG_PRINT_TREE { println!("      Out data size: {}", out_size); };

            //OUDestinationDesc needs one of OUSWFileVersionDesc(0x0B), OUPartitionVersionDesc(0x0A), OUCMACDataDesc(0x11). Their structure is the same. so we can store the type
            let type_descriptor: DescriptorHeader = reader.read_be()?;
            if ![0x0B, 0xA, 0x11].contains(&type_descriptor.tag) {return Err(format!("Unexpected descriptor type in OUDestinationDesc, Expected: one of 0x0B, 0x0A, 0x11, Got: 0x{:02x}!", type_descriptor.tag).into())}
            if CONFIG_PRINT_TREE { println!("      Type descriptor(0x{:02x}) - Size: {}", type_descriptor.tag, type_descriptor.size); };
            let destination_info: CommonDestinationInfo = reader.read_be()?;
            if CONFIG_PRINT_TREE { 
                println!("          Name lenght: {}", destination_info.name_len);
                println!("          Name: {}", destination_info.name());
                println!("          Version: {}", destination_info.version);
            };

            //OUDataProcessingDesc can have OUXOREncryptionDesc(0x0D), OUAESEncryptionDesc(0x0E), OUCompressionDesc(0x0F), OUSecureHashValidationDesc(0x18), OURSAValidationDesc(0x10), OUDataCopyDesc(0x16), OUKeepCurrentDataDesc(0x1E), OUCRC32ValidationDesc(0x12)
            let data_processing_descriptor: DescriptorHeader = reader.read_be()?;
            if data_processing_descriptor.tag != 0x07 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x07, Got: 0x{:02x}!", data_processing_descriptor.tag).into())}
            if CONFIG_PRINT_TREE { println!("  OUDataProcessingDesc(0x07) - Size: {}", data_processing_descriptor.size); };
            let heading_size: u32 = reader.read_be()?;
            if CONFIG_PRINT_TREE { println!("      Heading size: {}", heading_size); };
            let data_size: u32 = reader.read_be()?;
            if CONFIG_PRINT_TREE { println!("      Data size: {}", data_size); };

            let mut aes_encryption = false;
            //let mut crc32_hash: Option<u32> = None;
            //let mut secure_hash: Option<Vec<u8>> = None;

            let epos = reader.stream_position()? + (data_processing_descriptor.size - 8) as u64;
            while reader.stream_position()? < epos {
                let descriptor: DescriptorHeader = reader.read_be()?;
                if ![0x0D, 0x0E, 0x0F, 0x18, 0x10, 0x16, 0x1E, 0x12].contains(&descriptor.tag) {return Err(format!("Unexpected descriptor type in OUDataProcessingDesc, Expected: one of 0x0D, 0x0E, 0x0F, 0x18, 0x10, 0x16, 0x1E, 0x12, Got: 0x{:02x}!", descriptor.tag).into())}
                if descriptor.tag == 0x0E {
                    //OUAESEncryptionDesc
                    if CONFIG_PRINT_TREE { println!("          OUAESEncryptionDesc(0x0E) - Size: {}", descriptor.size); };
                    let aes_encryption_desc: OUAESEncryptionDesc = reader.read_be()?;   
                    if CONFIG_PRINT_TREE { 
                        println!("              Mode: {}", aes_encryption_desc.mode);
                        println!("              Key size: {}", aes_encryption_desc.key_size);
                        println!("              Salt size: {}", aes_encryption_desc.salt_size);
                    };
                    aes_encryption = true;
                }
                else if descriptor.tag == 0x10 {
                    //OURSAValidationDesc
                    if CONFIG_PRINT_TREE { println!("          OURSAValidationDesc(0x10) - Size: {}", descriptor.size); };
                    let rsa_validation_desc: OURSAValidationDesc = reader.read_be()?;
                    if CONFIG_PRINT_TREE { 
                        println!("              Mode: {}", rsa_validation_desc.mode);
                        println!("              Field 2: {}", rsa_validation_desc._unknown);
                        println!("              Signature size: {}", rsa_validation_desc.signature_size);
                    };
                }
                else if descriptor.tag == 0x12 {
                    //OUCRC32ValidationDesc
                    if CONFIG_PRINT_TREE { println!("          OUCRC32ValidationDesc(0x12) - Size: {}", descriptor.size); };
                    let crc32: u32 = reader.read_be()?;
                    if CONFIG_PRINT_TREE { println!("              CRC32: {:02x}", crc32); };
                    //crc32_hash = Some(crc32);
                }
                else if descriptor.tag == 0x18 {
                    //OUSecureHashValidationDesc
                    if CONFIG_PRINT_TREE { println!("          OUSecureHashValidationDesc(0x18) - Size: {}", descriptor.size); };
                    let secure_hash_validation_desc: OUSecureHashValidationDesc = reader.read_be()?;
                    if CONFIG_PRINT_TREE { 
                        println!("              Mode: {}", secure_hash_validation_desc.mode);
                        println!("              Hash size: {}", secure_hash_validation_desc.hash_size);
                        println!("              Hash: {}", hex::encode(&secure_hash_validation_desc.hash));
                    };
                    //secure_hash = Some(secure_hash_validation_desc.hash);
                }
                else {
                    //type not implemented,  ignore the data
                    if CONFIG_PRINT_TREE { println!("          Unimplemented descriptor(0x{:02x}) - Size: {}", descriptor.tag, descriptor.size); };
                    let _descriptor_data = common::read_exact(&mut reader, descriptor.size as usize);
                }     
            }

            //OUGroupInfoDesc
            let group_info_descriptor: DescriptorHeader = reader.read_be()?;
            if group_info_descriptor.tag != 0x13 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x13, Got: 0x{:02x}!", group_info_descriptor.tag).into())}
            if CONFIG_PRINT_TREE { println!("  OUGroupInfoDesc(0x13) - Size: {}", group_info_descriptor.size); };
            let group_id: u32 = reader.read_be()?;
            if CONFIG_PRINT_TREE { println!("      Group ID: {}", group_id); };

            //create the msd item with all infos
            let msd_item = MSDItem {
                item_id: item_id,
                item_type: type_descriptor.tag,
                all_size: chunk.value,
                name: destination_info.name(),
                heading_size: heading_size,
                data_size: data_size,

                aes_encryption: aes_encryption,
                //crc32_hash: crc32_hash,
                //secure_hash: secure_hash,
            };
            items.push(msd_item);

            //go directly to the end of the chunk to skip optional descriptors just in case
            reader.seek(SeekFrom::Start(chunk_end))?;
        }

        else if top_descriptor.tag == 0x02 {
            if CONFIG_PRINT_TREE { println!("OUGroupDesc(0x02) - Size: {}", top_descriptor.size); };
            let group_desc: OUGroupDesc = reader.read_be()?;
            if CONFIG_PRINT_TREE { 
                println!("  Group ID: {}", group_desc.group_id);
                println!("  Field 2: {}", group_desc.field_2);
                println!("  Field 3: {}", group_desc.field_3);
            };

            //OUGroupDesc REQUIRES one of: OUSWImageVersionDesc(0x09), OUSWImageVersionExDesc(0x19), OUOptionalDataVersionDesc(0x14), OUFirmwareVersionDesc(0x15). OPTIONALLY it can also have OUDependenciesDesc
            //MSD files seem to exclusively use OUSWImageVersionExDesc
            let version_descriptor: DescriptorHeader = reader.read_be()?;
            if ![0x09, 0x19, 0x14, 0x15].contains(&version_descriptor.tag) {return Err(format!("Unexpected descriptor type in OUGroupDesc, Expected: one of 0x09, 0x19, 0x14, 0x15, Got: 0x{:02x}!", version_descriptor.tag).into())}
            if version_descriptor.tag == 0x19 {
                if CONFIG_PRINT_TREE { println!("  OUSWImageVersionExDesc(0x12) - Size: {}", version_descriptor.size); };
                let sw_image_version_ex_desc: OUSWImageVersionExDesc = reader.read_be()?;
                if CONFIG_PRINT_TREE { 
                    println!("      Name lenght: {}", sw_image_version_ex_desc.name_len);
                    println!("      Name: {}", sw_image_version_ex_desc.name());
                    println!("      Major version: {}", sw_image_version_ex_desc.major_ver);
                    println!("      Minor version: {}", sw_image_version_ex_desc.minor_ver);
                    println!("      Date year: {}", sw_image_version_ex_desc.date_year);
                    println!("      Date month: {}", sw_image_version_ex_desc.date_month);
                    println!("      Date day: {}", sw_image_version_ex_desc.date_day);
                };

                info = Some(sw_image_version_ex_desc);
            }
            else {
                //type not implemented,  ignore the data
                if CONFIG_PRINT_TREE { println!("  Unimplemented descriptor(0x{:02x}) - Size: {}", version_descriptor.tag, version_descriptor.size); };
                let _descriptor_data = common::read_exact(&mut reader, version_descriptor.size as usize);
            }            
            
            //go directly to the end of the chunk to skip optional descriptors just in case
            reader.seek(SeekFrom::Start(chunk_end))?;
        }

        else {
            return Err(format!("Unexpected top level descriptor type 0x{:02x}!", top_descriptor.tag).into());
        }
    }

    Ok((items, info)) //finally, it will return a list of MSD items and info about image if it was collected.
}
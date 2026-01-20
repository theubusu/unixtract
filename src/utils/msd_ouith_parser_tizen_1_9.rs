//MAIN CODE: https://github.com/theubusu/msd_OUITH_parser

use std::io::{Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

// whether to print the tree
static CONFIG_PRINT_TREE: bool = false;

#[derive(BinRead)]
struct DescriptorHeader {
    _flag: u8,
    size: u32, //size includes the next TAG value
    tag: u32,
}

#[derive(BinRead)]
struct OUUpgradeItemDesc {
    _flag: u8,
    item_id: u32,
    unk_flag: u8,
    original_size: u64,
    processed_size: u64,
    unk: u16,
}

#[derive(BinRead)]
struct OUDataProcessingDesc {
    _flag: u8,
    subdesc_count: u32,
}

#[derive(BinRead)]
struct OUGroupInfoDesc {
    _flag: u8,
    group_id: u32,
}

#[derive(BinRead)]
struct OUCRC32ValidationDesc {
    _flag: u8,
    crc32: u32,
}

#[derive(BinRead)]
struct OURSAValidationDesc {
    _flag: u8,
    public_key_id: u32,
    signature_size: u16,
    #[br(count = signature_size)] signature: Vec<u8>,
}

#[derive(BinRead)]
struct OUAESEncryptionDesc {
    _flag: u8,
    salt_size: u8,
    #[br(count = salt_size)] salt: Vec<u8>,
    processed_size: u64,
}

#[derive(BinRead)]
struct OUGroupDesc {
    _flag: u8,
    group_id: u32,
}

#[derive(BinRead)]
pub struct OUSWImageVersionDesc {
    pub _flag: u8,
    pub name_len: u8,
    #[br(count = name_len)] pub name_bytes: Vec<u8>,
    pub major_ver: u16,
    pub minor_ver: u16,
}
impl OUSWImageVersionDesc {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct OUPartitionVersionDesc {
    _flag: u8,
    name_len: u8,
    #[br(count = name_len)] name_bytes: Vec<u8>,
}
impl OUPartitionVersionDesc {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct OUSecureDowngradeDesc {
    _flag: u8,
    image_generation_date: u32,
    _unk1: u32,
    _unk2: u32,
}

//this is a struct that will communicate all values important when parsing the MSD file.
pub struct MSDItem {
    pub item_id: u32,
    pub name: String,

    //pub crc32_hash: Option<u32>,
    pub aes_encryption: bool,
    pub aes_salt: Option<Vec<u8>>,
}

pub fn parse_blob_1_9(blob: &[u8]) -> Result<(Vec<MSDItem>, Option<OUSWImageVersionDesc>), Box<dyn std::error::Error>> {
    let mut reader = Cursor::new(blob);
    let mut items: Vec<MSDItem> = Vec::new();
    let mut info: Option<OUSWImageVersionDesc> = None;

    let _public_key_id: u32 = reader.read_le()?;
    let signature_size: u16 = reader.read_le()?;
    let _signature = common::read_exact(&mut reader, signature_size as usize)?; //signature included at the beginning of blob in MSD file

    let magic = common::read_exact(&mut reader, 51)?;
    if magic != b"Tizen Software Upgrade Tree Binary Format ver. 1.9\x00" {
        return Err(format!("Invalid tree magic!").into())
    }

    let top_level_descriptor_count: u32 = reader.read_le()?;
    if CONFIG_PRINT_TREE { println!("\nTop level descriptor count: {}", top_level_descriptor_count); };

    for _i in 0..top_level_descriptor_count {
        //parse top level descriptor. it can only be ID 1(OUUpgradeItemDesc) or 2(OUGroupDesc) or 0x37(OUSecureDowngradeDesc)
        let top_descriptor: DescriptorHeader = reader.read_le()?;
        if top_descriptor.tag == 0x01 {
            if CONFIG_PRINT_TREE { println!("OUUpgradeItemDesc(0x01) - Size: {}", top_descriptor.size); };
            let upgrade_item_desc: OUUpgradeItemDesc = reader.read_le()?;
            if CONFIG_PRINT_TREE { 
                println!("  Item ID: {}", upgrade_item_desc.item_id);
                println!("  Unknown flag: {}", upgrade_item_desc.unk_flag);
                println!("  Original size: {}", upgrade_item_desc.original_size);
                println!("  Processed size: {}", upgrade_item_desc.processed_size);
                println!("  Unknown: {}", upgrade_item_desc.unk);
            };

            let subdesc_count: u32 = reader.read_le()?;
            if CONFIG_PRINT_TREE { println!("  Subdescriptor count: {}", subdesc_count); };

            let mut name: Option<String> = None;
            //let mut crc32_hash: Option<u32> = None;
            let mut aes_encryption = false;
            let mut aes_salt: Option<Vec<u8>> = None;

            for _i in 0..subdesc_count {
                let sub_descriptor: DescriptorHeader = reader.read_le()?;
                if sub_descriptor.tag == 0x0A {
                    if CONFIG_PRINT_TREE { println!("      OUPartitionVersionDesc(0x0A) - Size: {}", sub_descriptor.size); };
                    let partition_version_desc: OUPartitionVersionDesc = reader.read_le()?;
                    if CONFIG_PRINT_TREE { 
                        println!("          Name lenght: {}", partition_version_desc.name_len);
                        println!("          Name: {}", partition_version_desc.name());
                    };

                    name = Some(partition_version_desc.name());
                }
                else if sub_descriptor.tag == 0x07 {
                    if CONFIG_PRINT_TREE { println!("      OUDataProcessingDesc(0x07) - Size: {}", sub_descriptor.size); };
                    let data_processing_desc: OUDataProcessingDesc = reader.read_le()?;
                    if CONFIG_PRINT_TREE { println!("          Subdescriptor count: {}", data_processing_desc.subdesc_count); };

                    for _i in 0..data_processing_desc.subdesc_count {
                        let data_processing_sub_desc: DescriptorHeader = reader.read_le()?;
                        if data_processing_sub_desc.tag == 0x12 {
                            if CONFIG_PRINT_TREE { println!("              OUCRC32ValidationDesc(0x12) - Size: {}", data_processing_sub_desc.size); };
                            let crc32_validation_desc: OUCRC32ValidationDesc = reader.read_le()?;
                            if CONFIG_PRINT_TREE { println!("                  CRC32: {:02x}", crc32_validation_desc.crc32); };

                            //crc32_hash = Some(crc32_validation_desc.crc32);
                        }
                        else if data_processing_sub_desc.tag == 0x10 {
                            if CONFIG_PRINT_TREE { println!("              OURSAValidationDesc(0x10) - Size: {}", data_processing_sub_desc.size); };
                            let rsa_validation_desc: OURSAValidationDesc = reader.read_le()?;
                            if CONFIG_PRINT_TREE { 
                                println!("                  Signature size: {}", rsa_validation_desc.signature_size);
                                println!("                  Public key ID: {}", rsa_validation_desc.public_key_id);
                                println!("                  Signature: {}", hex::encode(&rsa_validation_desc.signature));
                            };
                        }
                        else if data_processing_sub_desc.tag == 0x0E {
                            if CONFIG_PRINT_TREE { println!("              OUAESEncryptionDesc(0x0E) - Size: {}", data_processing_sub_desc.size); };
                            let aes_encryption_desc: OUAESEncryptionDesc = reader.read_le()?;
                            if CONFIG_PRINT_TREE { 
                                println!("                  Salt size: {}", aes_encryption_desc.salt_size);
                                println!("                  Salt: {}", hex::encode(&aes_encryption_desc.salt));
                                println!("                  Processed size: {}", aes_encryption_desc.processed_size);
                            };
                            
                            aes_encryption = true;
                            aes_salt = Some(aes_encryption_desc.salt);
                        }
                        else {
                            if CONFIG_PRINT_TREE { println!("              Unimplemented Descriptor(0x{:02x}) - Size: {}", data_processing_sub_desc.tag, data_processing_sub_desc.size); };
                            let _ = common::read_exact(&mut reader, data_processing_sub_desc.size as usize - 4)?;

                        }
                    }
                }
                else if sub_descriptor.tag == 0x13 {
                    if CONFIG_PRINT_TREE { println!("      OUGroupInfoDesc(0x13) - Size: {}", sub_descriptor.size); };
                    let group_info_desc: OUGroupInfoDesc = reader.read_le()?;
                    if CONFIG_PRINT_TREE { println!("          Group ID: {}", group_info_desc.group_id); };
                }
                else {
                    if CONFIG_PRINT_TREE { println!("      Unimplemented Descriptor(0x{:02x}) - Size: {}", sub_descriptor.tag, sub_descriptor.size); };
                    let _ = common::read_exact(&mut reader, sub_descriptor.size as usize - 4)?;
                }   
            }

            if let Some(name) = name {
                //create the msd item with all infos
                let msd_item = MSDItem {
                    item_id: upgrade_item_desc.item_id,
                    name: name,

                    //crc32_hash: crc32_hash,
                    aes_encryption: aes_encryption,
                    aes_salt: aes_salt,
                };
                items.push(msd_item);
            } else {
                //if no name found panic because it is required
                return Err(format!("Could not retrieve required Name for item ID {}", upgrade_item_desc.item_id).into()); 
            }  
        }
        else if top_descriptor.tag == 0x02 {
            if CONFIG_PRINT_TREE { println!("OUGroupDesc(0x02) - Size: {}", top_descriptor.size); };
            let group_desc: OUGroupDesc = reader.read_le()?;
            if CONFIG_PRINT_TREE { println!("  Group ID: {}", group_desc.group_id); };

            let subdesc_count: u32 = reader.read_le()?; //LITTLE ENDIAN??
            if CONFIG_PRINT_TREE { println!("  Subdescriptor count: {}", subdesc_count); };

            for _i in 0..subdesc_count {
                let sub_descriptor: DescriptorHeader = reader.read_le()?;
                if sub_descriptor.tag == 0x19 {
                    if CONFIG_PRINT_TREE { println!("      OUSWImageVersionDesc(0x19) - Size: {}", sub_descriptor.size); };
                    let sw_image_version_desc: OUSWImageVersionDesc = reader.read_le()?;
                    if CONFIG_PRINT_TREE { 
                        println!("          Name lenght: {}", sw_image_version_desc.name_len);
                        println!("          Name: {}", sw_image_version_desc.name());
                        println!("          Major ver: {}", sw_image_version_desc.major_ver);
                        println!("          Minor ver: {}", sw_image_version_desc.minor_ver);
                    };

                    info = Some(sw_image_version_desc);
                } else {
                    if CONFIG_PRINT_TREE { println!("      Unimplemented Descriptor (0x{:02x}) - Size: {}", sub_descriptor.tag, sub_descriptor.size); };
                    let _ = common::read_exact(&mut reader, sub_descriptor.size as usize - 4)?;
                }
            }
        }
        else if top_descriptor.tag == 0x37 {
            if CONFIG_PRINT_TREE { println!("OUSecureDowngradeDesc(0x37) - Size: {}", top_descriptor.size); };
            let secure_downgrade_desc: OUSecureDowngradeDesc = reader.read_le()?;
            if CONFIG_PRINT_TREE { println!("  Image generation timestamp: {}", secure_downgrade_desc.image_generation_date); };
        }
        else {
            return Err(format!("Unexpected top level descriptor type 0x{:02x}!", top_descriptor.tag).into()); 
        }

    }

    Ok((items, info)) //finally, it will return a list of MSD items and info about image if it was collected.
}
//MAIN CODE: https://github.com/theubusu/msd_OUITH_parser

use std::io::{Seek, SeekFrom, Cursor};
use binrw::{BinRead, BinReaderExt};

use crate::utils::common;

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
    _name_len: u8,
    #[br(count = _name_len)] name_bytes: Vec<u8>,
    _version: u16,
}
impl CommonDestinationInfo {
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
}

#[derive(BinRead)]
struct OUAESEncryptionDesc {
    _mode: u8,
    _key_size: u32,
    _salt_size: u32,
}

#[derive(BinRead)]
struct OURSAValidationDesc {
    _mode: u8,
    _unknown: u32,
    _signature_size: u32,
}

#[derive(BinRead)]
struct OUSecureHashValidationDesc {
    _mode: u8,
    _hash_size: u16,
    #[br(count = _hash_size)] hash: Vec<u8>,
}

#[derive(BinRead)]
struct OUGroupDesc {
    _group_id: u32,
    _field_2: u8,
    _field_3: u8,
}

#[derive(BinRead)]
pub struct OUSWImageVersionExDesc {
    pub _name_len: u8,
    #[br(count = _name_len)] pub name_bytes: Vec<u8>,
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
    
    let mut _chunk_n = 0;
    while reader.stream_position()? < blob.len() as u64 {
        _chunk_n += 1;
        let chunk: ChunkHeader = reader.read_be()?;
        let chunk_end = reader.stream_position()? + chunk.size as u64;

        //parse top level descriptor. it can only be ID 1(OUUpgradeItemDesc) or 2(OUGroupDesc)
        let top_descriptor: DescriptorHeader = reader.read_be()?;
        if top_descriptor.tag == 0x01 {
            let item_id: u32 = reader.read_be()?;

            //REQUIRED are items in order: OUDestinationDesc(0x03), OUDataProcessingDesc(0x07), OUGroupInfoDesc(0x13). OPTIONAL items: OUDependenciesDesc(0x04), OUDataPostProcessingDesc(0x08)
            //In MSD files, no others seem to be used than the required ones. We will ignore all data after required descriptors.
            let destination_descriptor: DescriptorHeader = reader.read_be()?;
            if destination_descriptor.tag != 0x03 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x03, Got: 0x{:02x}!", destination_descriptor.tag).into())}
            let _out_size: u32 = reader.read_be()?;

            //OUDestinationDesc needs one of OUSWFileVersionDesc(0x0B), OUPartitionVersionDesc(0x0A), OUCMACDataDesc(0x11). Their structure is the same. so we can store the type
            let type_descriptor: DescriptorHeader = reader.read_be()?;
            if ![0x0B, 0xA, 0x11].contains(&type_descriptor.tag) {return Err(format!("Unexpected descriptor type in OUDestinationDesc, Expected: one of 0x0B, 0x0A, 0x11, Got: 0x{:02x}!", type_descriptor.tag).into())}
            let destination_info: CommonDestinationInfo = reader.read_be()?;

            //OUDataProcessingDesc can have OUXOREncryptionDesc(0x0D), OUAESEncryptionDesc(0x0E), OUCompressionDesc(0x0F), OUSecureHashValidationDesc(0x18), OURSAValidationDesc(0x10), OUDataCopyDesc(0x16), OUKeepCurrentDataDesc(0x1E), OUCRC32ValidationDesc(0x12)
            let data_processing_descriptor: DescriptorHeader = reader.read_be()?;
            if data_processing_descriptor.tag != 0x07 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x07, Got: 0x{:02x}!", data_processing_descriptor.tag).into())}
            let heading_size: u32 = reader.read_be()?;
            let data_size: u32 = reader.read_be()?;

            let mut aes_encryption = false;
            let mut _crc32_hash: Option<u32> = None;
            let mut _secure_hash: Option<Vec<u8>> = None;

            let epos = reader.stream_position()? + (data_processing_descriptor.size - 8) as u64;
            while reader.stream_position()? < epos {
                let descriptor: DescriptorHeader = reader.read_be()?;
                if ![0x0D, 0x0E, 0x0F, 0x18, 0x10, 0x16, 0x1E, 0x12].contains(&descriptor.tag) {return Err(format!("Unexpected descriptor type in OUDataProcessingDesc, Expected: one of 0x0D, 0x0E, 0x0F, 0x18, 0x10, 0x16, 0x1E, 0x12, Got: 0x{:02x}!", descriptor.tag).into())}
                if descriptor.tag == 0x0E {
                    //OUAESEncryptionDesc
                    let _aes_encryption_desc: OUAESEncryptionDesc = reader.read_be()?;   
                    aes_encryption = true;
                }
                else if descriptor.tag == 0x10 {
                    //OURSAValidationDesc
                    let _rsa_validation_desc: OURSAValidationDesc = reader.read_be()?;
                }
                else if descriptor.tag == 0x12 {
                    //OUCRC32ValidationDesc
                    let crc32: u32 = reader.read_be()?;
                    _crc32_hash = Some(crc32);
                }
                else if descriptor.tag == 0x18 {
                    //OUSecureHashValidationDesc
                    let secure_hash_validation_desc: OUSecureHashValidationDesc = reader.read_be()?;
                    _secure_hash = Some(secure_hash_validation_desc.hash);
                }
                else {
                    //type not implemented,  ignore the data
                    let _descriptor_data = common::read_exact(&mut reader, descriptor.size as usize);
                }     
            }

            //OUGroupInfoDesc
            let group_info_descriptor: DescriptorHeader = reader.read_be()?;
            if group_info_descriptor.tag != 0x13 {return Err(format!("Unexpected descriptor type in OUUpgradeItemDesc, Expected: 0x13, Got: 0x{:02x}!", group_info_descriptor.tag).into())}
            let _group_id: u32 = reader.read_be()?;

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
            let _group_desc: OUGroupDesc = reader.read_be()?;

            //OUGroupDesc REQUIRES one of: OUSWImageVersionDesc(0x09), OUSWImageVersionExDesc(0x19), OUOptionalDataVersionDesc(0x14), OUFirmwareVersionDesc(0x15). OPTIONALLY it can also have OUDependenciesDesc
            //MSD files seem to exclusively use OUSWImageVersionExDesc
            let version_descriptor: DescriptorHeader = reader.read_be()?;
            if ![0x09, 0x19, 0x14, 0x15].contains(&version_descriptor.tag) {return Err(format!("Unexpected descriptor type in OUGroupDesc, Expected: one of 0x09, 0x19, 0x14, 0x15, Got: 0x{:02x}!", version_descriptor.tag).into())}
            if version_descriptor.tag == 0x19 {
                let sw_image_version_ex_desc: OUSWImageVersionExDesc = reader.read_be()?;

                info = Some(sw_image_version_ex_desc);
            }
            else {
                //type not implemented,  ignore the data
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
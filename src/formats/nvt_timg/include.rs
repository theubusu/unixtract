use crate::utils::common;
use binrw::BinRead;

#[derive(PartialEq, Eq, Debug)]
pub enum TimgVariant {
    Old,
    Old2,
    New,
}

pub trait TIMG {
    fn _magic_bytes(&self) -> Vec<u8>;
    fn data_size(&self) -> usize;
    fn _data_checksum(&self) -> [u8; 16];   //md5 of data_size after timg header
    fn _signature(&self) -> [u8; 256];
}

#[derive(Debug, BinRead)]
pub struct TIMG64 { //new
    _magic_bytes: [u8; 8], //TIMG/x00/x00/x00/x00
    data_size: u64,
    _data_checksum: [u8; 16],  
    _signature: [u8; 256],
}
impl TIMG for TIMG64 {
    fn _magic_bytes(&self) -> Vec<u8> {
        self._magic_bytes.to_vec()
    }
    fn data_size(&self) -> usize {
        self.data_size as usize
    }
    fn _data_checksum(&self) -> [u8; 16] {
        self._data_checksum
    }
    fn _signature(&self) -> [u8; 256] {
        self._signature
    }
}

#[derive(Debug, BinRead)]
pub struct TIMG32 {
    _magic_bytes: [u8; 4], //TIMG
    data_size: u32,
    _data_checksum: [u8; 16],
    _signature: [u8; 256],
}
impl TIMG for TIMG32 {
    fn _magic_bytes(&self) -> Vec<u8> {
        self._magic_bytes.to_vec()
    }
    fn data_size(&self) -> usize {
        self.data_size as usize
    }
    fn _data_checksum(&self) -> [u8; 16] {
        self._data_checksum
    }
    fn _signature(&self) -> [u8; 256] {
        self._signature
    }
}

#[derive(Debug, BinRead)]
pub struct TIMGOld2 {
    _magic_bytes: [u8; 4], //TIMG
    data_size: u32,
    _data_checksum: [u8; 16],
    _pad: u32,
    _signature: [u8; 256],
}
impl TIMG for TIMGOld2 {
    fn _magic_bytes(&self) -> Vec<u8> {
        self._magic_bytes.to_vec()
    }
    fn data_size(&self) -> usize {
        self.data_size as usize
    }
    fn _data_checksum(&self) -> [u8; 16] {
        self._data_checksum
    }
    fn _signature(&self) -> [u8; 256] {
        self._signature
    }
}

pub trait PIMG {
    fn magic_bytes(&self) -> Vec<u8>;
    fn name(&self) -> String;
    fn size(&self) -> usize;
    fn _checksum(&self) -> [u8; 16];    //md5 of stored data
    fn dest_dev(&self) -> String;
    fn comp_type(&self) -> String;
    fn comment(&self) -> String;
}

#[derive(Debug, BinRead)]
pub struct PIMG64 {
    magic_bytes: [u8; 8], //PIMG\x00\x00\x00\x00
    size: u64,
    _checksum: [u8; 16],
    name_bytes: [u8; 16],
    dest_dev_bytes: [u8; 64],
    comp_type_bytes: [u8; 16],
    _unknown1: u32,
    comment_bytes: [u8; 1024],
    _unknown2: u32,
}
impl PIMG for PIMG64 {
    fn magic_bytes(&self) -> Vec<u8> {
        self.magic_bytes.to_vec()
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn size(&self) -> usize {
        self.size as usize
    }
    fn _checksum(&self) -> [u8; 16] {
        self._checksum
    }
    fn dest_dev(&self) -> String {
        common::string_from_bytes(&self.dest_dev_bytes)
    }
    fn comp_type(&self) -> String {
        common::string_from_bytes(&self.comp_type_bytes)
    }
    fn comment(&self) -> String {
        common::string_from_bytes(&self.comment_bytes)
    }
}

#[derive(Debug, BinRead)]
pub struct PIMG32 {
    magic_bytes: [u8; 4], //PIMG
    size: u32,
    _checksum: [u8; 16],
    name_bytes: [u8; 16],
    dest_dev_bytes: [u8; 32],
    comp_type_bytes: [u8; 16],
    _unknown1: u32,
    comment_bytes: [u8; 1024],
    _unknown2: u32,
}
impl PIMG for PIMG32 {
    fn magic_bytes(&self) -> Vec<u8> {
        self.magic_bytes.to_vec()
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn size(&self) -> usize {
        self.size as usize
    }
    fn _checksum(&self) -> [u8; 16] {
        self._checksum
    }
    fn dest_dev(&self) -> String {
        common::string_from_bytes(&self.dest_dev_bytes)
    }
    fn comp_type(&self) -> String {
        common::string_from_bytes(&self.comp_type_bytes)
    }
    fn comment(&self) -> String {
        common::string_from_bytes(&self.comment_bytes)
    }
}

#[derive(Debug, BinRead)]
pub struct PIMGOld2 {
    magic_bytes: [u8; 4], //PIMG
    size: u32,
    _checksum: [u8; 16],
    name_bytes: [u8; 16],
    dest_dev_bytes: [u8; 24],
    comp_type_bytes: [u8; 16],
    _unknown1: u32,
}
impl PIMG for PIMGOld2 {
    fn magic_bytes(&self) -> Vec<u8> {
        self.magic_bytes.to_vec()
    }
    fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    fn size(&self) -> usize {
        self.size as usize
    }
    fn _checksum(&self) -> [u8; 16] {
        self._checksum
    }
    fn dest_dev(&self) -> String {
        common::string_from_bytes(&self.dest_dev_bytes)
    }
    fn comp_type(&self) -> String {
        common::string_from_bytes(&self.comp_type_bytes)
    }
    fn comment(&self) -> String {
        "".to_string()  //yes (this variant has no comment)
    }
}
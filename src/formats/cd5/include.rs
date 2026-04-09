use binrw::BinRead;

//all big endian

#[derive(BinRead)]
pub struct DescriptorHeader {
    pub magic: u8,
    pub size: u16,
}

#[derive(BinRead)]
pub struct DownloadHeader {
    // preceeded by DescriptorHeader
    pub manufacturer_code: u16,
    pub hardware_version: u16,
    _unk1: u16,
    _unk2: u16,
    pub variant: u16,
    pub sub_variant: u16,
    _unk_string_bytes: [u8; 8],
    pub version: u16,   // DSN/download sequence number
    pub module_count: u16,
    #[br(count=module_count)] pub module_entries: Vec<DownloadHeaderModuleEntry>,
    _signature_size: u16,
    #[br(count=_signature_size)] pub _signature: Vec<u8>,
    _extra_data_size: u16,
    #[br(count=_extra_data_size)] pub _extra_data: Vec<u8>,
    _checksum: u16,     //crc16 of header (not including magic and size)
}

#[derive(BinRead)]
pub struct DownloadHeaderModuleEntry {
    pub module_id: u16,
    pub version: u16 //DSN
}

#[derive(BinRead)]
pub struct ModuleDownloadHeader {
    // preceeded by DescriptorHeader
    pub module_id: u16,
    flags: u8,
    pub out_size: u32,
    pub segment_size: u16,
    pub segment_count: u16,
    _checksum: u16,     //crc16 of header (not including magic and size)
}
impl ModuleDownloadHeader {
    pub fn is_encrypted(&self) -> bool {
        (self.flags & (1 << 5)) != 0
    }
}

#[derive(BinRead)]
pub struct DownloadSegment {
    pub magic: u8,
    pub module_id: u16,
    pub data_size: u16,
    #[br(count=data_size)] pub data: Vec<u8>,
    _checksum: u16, //crc16 of module_id+size+(STORED)data
}

#[derive(BinRead)]
pub struct InnerModuleHeader {
    _module_id: u16,
    pub header_size: u16,
    pub data_size: u32,
    _unk1: u8,
    _version: u16,  //dsn
    _variant: u16,
    _sub_variant: u16,
    _version2: u16,
    _unk2: [u8; 5],
    _signature1_size: u16,
    #[br(count=_signature1_size)] pub _signature1: Vec<u8>,
    _signature2_size: u16,
    #[br(count=_signature2_size)] pub _signature2: Vec<u8>,
    _checksum: u32,     //crc32 of header
}
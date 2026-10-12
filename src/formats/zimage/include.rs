use binrw::BinRead;
use crate::utils::common;

#[derive(BinRead, Debug)]
#[br(assert(format_version == 3 || format_version == 5, "unknown format version {}", format_version ))]
pub struct ZimageHeader {
    _magic1: u32,   //5A696D67 ("Zimg")
    _magic2: u32,   //A5969298
    _reserved1: u16,
    pub format_version: u16,
    _crc: u32,
    _data_start: u32,    //or header total size
    _unk1: u32,
    _unk2: u32,
    _unk3: u32,
    _unk4: u32,
    _unk5: u32,
    _unk6: u32,
    pub release_version: u16,
    pub model: u8,
    _sub_model: u8,
    pub page_size: u32,
    pub spare_size: u32,
    _pages_per_block: u32,
    _block_count: u32,
    pub module_count: u32,
    _module_table_offset: u32,
    pub file_total_size: u32,
    _header_offset: u32,        //0x2000

    //for v5
    #[br(if(format_version == 5, 0))]
    _compressed_chunk_size: u32,

    #[br(if(format_version == 5, 0))]
    _pad: u32,
    //

    #[br(count = if format_version==5 {_module_table_offset-0x58} else {_module_table_offset-0x50})] pub image_name_bytes: Vec<u8>,

    //at module table offset now
    #[br(count = module_count)] pub modules: Vec<ModuleEntry>,
}
impl ZimageHeader {
    pub fn image_name(&self) -> String {
        common::string_from_bytes(&self.image_name_bytes)
    }
}

#[derive(BinRead, Debug)]
pub struct ModuleEntry {
    pub module_type: u8,
    pub subtype: u8,
    pub flags: u16,
    _name_offset: u16,
    _entry_size: u16,
    pub data_offset: u32,
    pub flash_offset: u32,
    pub flash_size: u32,
    _flash_size_no_spare: u32,
    pub stored_size: u32,
    pub partition_size: u32,
    _rsv1: u32,
    _rsv2: u32,
    #[br(count = _entry_size - 40)] pub module_name_bytes: Vec<u8>,
    
    //pad to 4
    #[br(count = (((_entry_size + 3) / 4) * 4) - _entry_size )] _padding: Vec<u8>,
}
impl ModuleEntry {
    pub fn module_name(&self) -> String {
        common::string_from_bytes(&self.module_name_bytes)
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x1C00 != 0
    }
}
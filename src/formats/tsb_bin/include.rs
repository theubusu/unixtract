use crate::utils::common;
use binrw::BinRead;

#[derive(BinRead)]
pub struct Header {
    _signature: [u8; 128],
    _control_id: u32,               //must be zero
    pub lenght: u32,                //file size
    pub entry_count: u32,
    _pad1: [u8; 4],
    build_no_bytes: [u8; 16],
    _maker_id: u32,
    _model_id: u32,
    _group_id: u32,
    _target_version: u32,       
    _entry_addr: u32,
    _pad3: [u8; 12],
    _tsb_bin_ver: u32,              //known is 3
    _pad4: [u8; 12],
    _active_flag: u32,              //used in NAND to mark the active boot slot
    _pad5: [u8; 24],
    _key_component: u32,            //used for calculating key for old type "signature"
    _pad6: [u8; 8],
    _image_checksum: u32,           //sum 256..1024
    _header_checksum: u32,          //sum 0..252
    #[br(count=entry_count)] pub entries: Vec<Entry>,
}
impl Header {
    pub fn build_no(&self) -> String {
        common::string_from_bytes(&self.build_no_bytes)
    }
}

#[derive(BinRead)]
pub struct Entry {
    name_bytes: [u8; 4],
    image_flag: u32,
    pub offset: u32,
    pub size: u32,
    pub load_addr: u32,
    _pad1: [u8; 8],
    _image_checksum: u32,
    _pad2: [u8; 32],
}
impl Entry {
    pub fn name(&self) -> String {
        common::string_from_bytes(&self.name_bytes)
    }
    pub fn is_compressed(&self) -> bool {
        (self.image_flag & 1 << 4) != 0
    }
}

pub fn is_valid_header_checksum(header_data: &[u8]) -> bool {
    if header_data.len() < 256 {
        return false;
    }

    //calc first sum 63*4 = 252 bytes
    let calc: u32 = header_data[..252]
        .chunks_exact(4)
        .map(|ch| {u32::from_be_bytes(ch.try_into().unwrap())})
        .fold(0u32, |a, x| a.wrapping_add(x));

    //expected checksum at end
    let exp = u32::from_be_bytes(header_data[252..256].try_into().unwrap());

    calc == exp &&  exp != 0 /* for false positive (SHOULD BE IMPROVED) */
}
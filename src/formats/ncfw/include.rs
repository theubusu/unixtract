use binrw::BinRead;

#[derive(BinRead)]
pub struct NcfwHeader {
    _magic: [u8; 4],        //b"NCFW"
    _none: u32,
    pub total_size: u32,
    pub header_size: u32,
    pub data_size: u32,
    pub encryption_type: u32,
    pub signature_size: u32,
    _none2: u32
}

#[derive(BinRead)]
pub struct NcaHeader {
    pub magic: [u8; 4],        //b"\xAF\xAF\x9C\x9C"
    pub dest_address: u32,
    pub date: u32,
    _none: u32,
    _tag: u32,                 //? b"\x58\x58\x78\x78"
    pub version_major: u8,
    pub version_minor: u8,
    _compressed: u8,
    pub nca_type: u8,
    pub size: u32,
    pub data_out_size: u32,
    _none2: u32,
    _vaddress: u32,
    _pad: [u8; 20],
    _checksum: u32,
}

pub fn decrypt0(enc_data: &[u8]) -> Vec<u8> {
    let mut data = enc_data.to_vec();

    for (i, byte) in data.iter_mut().enumerate() {
        let i_u8 = (i & 0xFF) as u8;
        let tmp = byte.wrapping_sub(i_u8).wrapping_sub(1);

        let shifted = ((tmp as u16) << 1) | ((tmp >> 7) as u16);
        *byte = (!shifted) as u8;
    }

    data
}

pub fn decrypt1(enc_data: &[u8]) -> Vec<u8> {
    let mut data = enc_data.to_vec();
    let mut state: u8 = 0xFF;

    for (i, byte) in data.iter_mut().enumerate() {
        let org = *byte;
        let pos = i;
        let rot = (pos & 7) as u32;

        let pos_u8 = (pos & 0xFF) as u8;
        let tmp = org.wrapping_sub(pos_u8).wrapping_sub(0x80);

        let mut val = tmp.rotate_left(rot & 7) ^ state;
        if (pos & 0x3F) != 0 {
            val = !val;
        }

        *byte = val;
        state = org;
    }

    data
}
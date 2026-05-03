use binrw::BinRead;

pub static KNOWN_MODULES: &[&str] = &[
    "Host",
    "EMMA",
    "EOPE",
    "Writer1",
    "Writer2",
    "unknown",
    "FrontMicom",
    "Kernel",
    "RootFS",
    "FontData",
    "MultiBoot",
    "AquosAudio",
];

#[derive(PartialEq)]
pub enum HeaderType {
    RVP,
    MVP,
}

#[derive(BinRead)]
pub struct RVPHeader {
    _crc: u32,
    _sum: u32,
    pub force: u32,                 //3 = force
    pub year: u32,                  //as hex
    version_info_bytes: [u8; 48],  //EUC_JP encoded as fullwidth
}
impl RVPHeader {
    pub fn version_info(&self) -> String {
        eucjp_fullwidth_to_ascii(&self.version_info_bytes)
    }
}

// HAX
fn eucjp_fullwidth_to_ascii(data: &[u8]) -> String {
    let mut out = String::new();

    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0xA3 {
            let c = (data[i + 1] - 0x80) as char;
            out.push(c);
        }
        i += 2;
    }

    out
}

pub fn decrypt_xor(data: &[u8]) -> Vec<u8> {
    let key_bytes = b"\xCC\xF0\xC8\xC4\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA";
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}
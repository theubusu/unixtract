use binrw::BinRead;

use rsa::{BigUint};

pub fn decrypt_key_header(ciphertext: &[u8], n_bytes: &[u8]) -> Vec<u8> {
    let n = BigUint::from_bytes_be(n_bytes);
    let d = BigUint::from_bytes_be(b"\x01\x00\x01");
    let c = BigUint::from_bytes_be(ciphertext);

    let m = c.modpow(&d, &n);

    let key_size = n_bytes.len();
    let mut out = m.to_bytes_be();
    if out.len() < key_size {
        let mut padded = vec![0u8; key_size - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    out
}

pub static CLEAR_HEADER_SIGNATURE: &[u8; 16] = b"BDC\tCDB\tBDC\tCDB\t";

#[derive(BinRead)]
pub struct ClearHeader {
    pub signature: [u8;16],         //"BDC\tCDB\tBDC\tCDB\t"
    pub clear_header_version: u8,
    pub key_header_version: u8,
    pub key_header_type: u8,
    _none1: u8,
    pub oui: u32,
    pub mg: u32,
    pub module_size: u32,
}

#[derive(BinRead)]
pub struct KeyHeader {
    _header_type: u8,
    _verification_mode: u8,
    pub cipher_type: u8,
    _none1: u8,
    _key_size: u32,
    pub key: [u8; 16],
    _key2: [u8; 16],
    _digest: [u8; 32],      //sha256
    pub plaintext_length: u32,
    _encrypt_blocks: u32,
    _footer: [u8;16],         //"BDC\tCDB\tBDC\tCDB\t" (same as clear header sig)
}

pub static DECRYPTION_TRAILER: &[u8; 16] = b"CDB\tBDC\tCDB\tBDC\t";
pub static MOD_HDR_SIGNATURE: &[u8; 16] = b"BDC\tMOD\tSIG\tHDR\t";

#[derive(BinRead)]
pub struct ModuleHeader {
    pub signature: [u8;16],         //"BDC\tMOD\tSIG\tHDR\t"
    _version: u8,
    _none1: u8,
    pub header_size: u16,
    _none2: u16,
    _name_offset: u16,
    _module_version: u16,
    pub module_index: u16,
    _module_count: u16,
    _none3: u16,
    pub module_size: u32,
    pub module_offset: u32,
}


pub static COMP_DIR_SIGNATURE: &[u8; 16] = b"BDC\tCOM\tDIR\tSTR\t";

#[derive(Debug, BinRead)]
pub struct ComponentDirectoryHeader {
    pub signature: [u8;16],     //"BDC\tCOM\tDIR\tSTR\t"
    _version: u8,
    _a2: u8,
    _a3: u8,
    _a4: u8,
    _b1: u32,
    _strings_offset: u32,
    _oui: u32,
    _mg: u32,
    _b5: u32,
    _ver1: u16,
    _ver2: u16,
    _c1: u16,
    _c2: u16,
    _c3: u16,
    _c4: u16,
    pub component_count: u16,
    _e2: u16,
    pub string_table_size: u16,
}

#[derive(Debug, BinRead)]
pub struct ComponentDescriptor {
    _a1: u16,
    _a2: u16,
    _oui: u32,
    _mg: u16,
    pub name_offset: u16,
    pub module_version: u16,
    _ver2: u16,
    pub size: u32,
    _count1: u16,
    _count2: u16,
    _count3: u16,
    _count4: u16,
    pub module_count: u16,
    _u5: u16,

    #[br(count = _count1)] _c1: Vec<[u8;4]>,
    #[br(count = _count2)] _c2: Vec<[u8;4]>,
    #[br(count = _count3)] _c3: Vec<[u8;6]>,
    #[br(count = _count4)] _c4: Vec<[u8;4]>,

    #[br(count = module_count)] pub modules: Vec<ComponentModuleDescriptor>,
}

#[derive(Debug, BinRead)]
pub struct ComponentModuleDescriptor {
    pub offset: u32,
    pub plaintext_size: u32,
    pub module_size: u32,
    _hash: [u8; 32],
}
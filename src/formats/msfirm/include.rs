use sha1::{Sha1, Digest};
use std::collections::HashMap;

pub fn calc_hash(key: &[u8; 64], data: &[u8]) -> [u8; 20] {
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner_hasher = Sha1::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner = inner_hasher.finalize();

    let mut outer_hasher = Sha1::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner);
    outer_hasher.finalize().into()
}

pub fn decrypt_sha(key: &[u8; 64], data: &[u8]) -> Vec<u8> {
        let mut keystream = Vec::with_capacity(data.len());
        let mut digest: [u8; 20] = key[..20].try_into().unwrap();

        while keystream.len() < data.len() {
            let mut hasher = Sha1::new();
            hasher.update(&digest);
            hasher.update(&key[20..40]);
            digest = hasher.finalize().into();
            keystream.extend_from_slice(&digest);
        }

        data.iter()
            .zip(keystream.iter())
            .map(|(d, k)| d ^ k)
            .collect()
}

#[derive(Debug)]
pub struct ContentDat {
    _fv: usize,
    _sv: usize,
    pub datasize: usize,    // [alsiz]
    _chksum: usize,      // [hdsm]
    pub total_num: usize,   // [total number of files]
    pub files: Vec<FileEntry>
}
impl ContentDat {
    pub fn parse(data: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut sections = Vec::new();
        let mut curr: Option<HashMap<String, String>> = None;
        for line in data.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                if let Some(section) = curr.take() {
                    sections.push(section);
                }
                curr = Some(HashMap::new());
            } else if let Some((key, value)) = line.split_once('=') {
                if let Some(section) = curr.as_mut() {
                    section.insert(key.to_string(), value.to_string());
                }
            }
        }
        if let Some(section) = curr {
            sections.push(section);
        }
        let mut content = ContentDat {
            _fv: 0,
            _sv: 0,
            datasize: usize::from_str_radix(&sections[0]["datasize"], 16)?,
            _chksum: usize::from_str_radix(&sections[1]["chksum"], 16)?,
            total_num: usize::from_str_radix(&sections[2]["total_num"], 16)?,
            files: Vec::new(),
        };
        for section in sections.iter().skip(3) {
            let entry = FileEntry {
                fnum: usize::from_str_radix(&section["fnum"], 16)?,
                name: section["name"].clone(),
                offset: usize::from_str_radix(&section["offset"], 16)?,
                size: usize::from_str_radix(&section["size"], 16)?,
                _cksum: usize::from_str_radix(&section["cksum"], 16)?,
                _progress: if section.contains_key("progress") {Some(usize::from_str_radix(&section["progress"], 16)?)} else {None},
                encrypt: section["encrypt"] == "yes"
            };
            content.files.push(entry);
        }
        Ok(content)
    }
}

#[derive(Debug)]
pub struct FileEntry {
    pub fnum: usize,
    pub name: String,
    pub offset: usize,
    pub size: usize,
    _cksum: usize,
    _progress: Option<usize>,
    pub encrypt: bool,
}
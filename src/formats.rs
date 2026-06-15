use std::io::{Read, Seek, Write};

//definition format
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

// these are seperate because returning Self in open will cause issues
pub trait Format {
    fn name(&self) -> &str;
    fn open(&self, reader: &mut dyn ReadSeek) -> Result<Box<dyn FormatInstance>, Box<dyn std::error::Error>>;
}
pub trait WriteSeek: Write + Seek {}
impl<T: Write + Seek> WriteSeek for T {}

pub trait FormatInstance {
    fn get_file_properties(&self) -> Vec<FileProperty>;
    fn get_item_properties(&self, idx: usize) -> Vec<ItemProperty>;
    fn extract_item(&self, reader: &mut dyn ReadSeek, idx: usize, buf: &mut dyn WriteSeek) -> Result<(), Box<dyn std::error::Error>>;
}

pub enum FileProperty {
    Name(String),
    FileSize(usize),
    DataSize(usize),
    ItemCount(usize),
}

pub enum ItemProperty {
    Name(String),           //used in case of ex. section name, with no extension
    Path(String),           //used when name already has extension or path
    Size(usize),
}

#[macro_export]
macro_rules! get_prop {
    ($props:expr, $variant:path) => {
        $props.iter().find_map(|p| {
            if let $variant(value) = p {
                Some(value)
            } else {
                None
            }
        })
    };
}

//formats list
mod novatek;
mod tsb_bin;
mod invincible_image;
mod mtk_bdp;

pub fn get_formats() -> Vec<Box<dyn Format>> {
    vec![
        Box::new(crate::formats::novatek::NfwbFormat),
        Box::new(crate::formats::tsb_bin::TsbBinFormat),
        Box::new(crate::formats::invincible_image::InvincibleImageFormat),
        Box::new(crate::formats::mtk_bdp::MtkBdpFormat),
    ]
}
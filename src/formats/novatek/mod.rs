mod include;

use binrw::BinReaderExt;
use log::info;

use include::*;
use crate::utils::common;
use crate::formats::{Format, FormatInstance, ReadSeek, WriteSeek, FileProperty, ItemProperty};

pub struct NfwbFormat;
impl Format for NfwbFormat {
    fn name(&self) -> &str {
        "nfwb"
    }
    fn open(&self, mut reader: &mut dyn ReadSeek) -> Result<Box<dyn FormatInstance>, Box<dyn std::error::Error>> {
        let magic = common::read_at(reader, 0, 4)?;
        if magic != b"NFWB" {
            return Err("invalid magic".into());
        }
        let header: NfwbHeader = reader.read_le()?;
        Ok(Box::new(NfwbFile { header }))
    }
}

struct NfwbFile {
    header: NfwbHeader,
}
impl FormatInstance for NfwbFile {
    fn extract_item(&self, reader: &mut dyn ReadSeek, idx: usize, buf: &mut dyn WriteSeek) -> Result<(), Box<dyn std::error::Error>> {
        let item = &self.header.part_entries[idx];
        info!("ID: {}, offset: {}, size: {}", item.id, item.offset, item.size);

        let data = common::read_at(reader, item.offset as u64, item.size as usize)?;
        buf.write_all(&data)?;

        Ok(())
    }
    fn get_file_properties(&self) -> Vec<FileProperty> {
        vec! [
            FileProperty::Name(format!("{} {}.{}", self.header.firmware_name(), self.header.version_major, self.header.version_minor)),
            FileProperty::DataSize(self.header.data_size as usize),
            FileProperty::ItemCount(self.header.part_count as usize),
        ]
    }
    fn get_item_properties(&self, idx: usize) -> Vec<ItemProperty> {
        let item = &self.header.part_entries[idx];
        vec![
            ItemProperty::Name(format!("{}", item.id)),
            ItemProperty::Size(item.size as usize)
        ]
    }
}
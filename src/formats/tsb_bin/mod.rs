mod include;
mod tsb_des;

use std::io::Cursor;

use binrw::BinReaderExt;
use log::{info, debug};
use tsb_des::decrypt;

use include::*;
use crate::utils::common;
use crate::utils::compression::decompress_zlib;
use crate::formats::{Format, FormatInstance, ReadSeek, WriteSeek, FileProperty, ItemProperty};

pub struct TsbBinFormat;
impl Format for TsbBinFormat {
    fn name(&self) -> &str {
        "tsb_bin"
    }
    fn open(&self, mut reader: &mut dyn ReadSeek) -> Result<Box<dyn FormatInstance>, Box<dyn std::error::Error>> {
        let b_header = common::read_at(reader, 0, 0x400)?;
        if is_valid_header_checksum(&b_header[..256]) {
            let header: Header = reader.read_be()?;
            return Ok(Box::new( TsbBinFile {header, key: None}));
        }

        // -- failed, try with decrypt
        //derive key from FILE SIZE (yes)
  
        // we cant get the file size in ng2 directly so we need to seek to end and get the position
        reader.seek(std::io::SeekFrom::End(0))?;
        let file_size = reader.stream_position()? as u32;
        debug!("file size: {}", file_size);

        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&file_size.to_le_bytes());
        let inv = !file_size;
        key[4..].copy_from_slice(&inv.to_le_bytes());
        debug!("calc key: {:x?}", key);

        let dec_header = decrypt(&b_header, &key);
        if is_valid_header_checksum(&dec_header) {
            let mut hdr_rdr = Cursor::new(dec_header);
            let header: Header = hdr_rdr.read_be()?;

            return Ok(Box::new( TsbBinFile {header, key: Some(key)} ));
        } else {
            return Err("header checksum failed in both variants".into());
        }
    }
}

struct TsbBinFile {
    header: Header,
    key: Option<[u8; 8]>
}
impl FormatInstance for TsbBinFile {
    fn extract_item(&self, reader: &mut dyn ReadSeek, idx: usize, buf: &mut dyn WriteSeek) -> Result<(), Box<dyn std::error::Error>> {
        let item = &self.header.entries[idx];
        info!("Name: {}, Offset: {}, Size: {}, Load address: 0x{:02x}", item.name(), item.offset, item.size, item.load_addr);

        let mut data;
        if let Some(key) = self.key {
            let enc_data = common::read_at(reader, item.offset as u64, (item.size as usize + 7) & !7)?;  //read aligned to 8b blocks for decryption
            info!("- decrypting...");
            data = decrypt(&enc_data, &key);
            data.truncate(item.size as usize); //discard alignment
        } else {
            data = common::read_at(reader, item.offset as u64, item.size as usize)?;
        }
        
        if item.is_compressed() {
            info!("- decompressing...");
            data = decompress_zlib(&data)?;
        }

        buf.write_all(&data)?;

        Ok(())
    }
    fn get_file_properties(&self) -> Vec<FileProperty> {
        vec! [
            FileProperty::Name(self.header.build_no()),
            FileProperty::FileSize(self.header.lenght as usize),
            FileProperty::ItemCount(self.header.entry_count as usize),
        ]
    }
    fn get_item_properties(&self, idx: usize) -> Vec<ItemProperty> {
        let item = &self.header.entries[idx];
        vec![
            ItemProperty::Name(item.name()),
            ItemProperty::Size(item.size as usize)
        ]
    }
}
mod include;

use std::io::SeekFrom;

use binrw::BinReaderExt;
use log::{debug, info};

use include::*;
use crate::utils::common;
use crate::utils::aes::decrypt_aes128_cbc_pcks7;
use crate::formats::{Format, FormatInstance, ReadSeek, WriteSeek, FileProperty, ItemProperty};

pub struct InvincibleImageFormat;
impl Format for InvincibleImageFormat {
    fn name(&self) -> &str {
        "invincible_image"
    }
    fn open(&self, mut reader: &mut dyn ReadSeek) -> Result<Box<dyn FormatInstance>, Box<dyn std::error::Error>> {
        let magic = common::read_at(reader, 0, 16)?;
        if magic != b"INVINCIBLE_IMAGE" {
            return Err("invalid magic".into());
        }
        let header: Header = reader.read_le()?;

        //precalculate item offsets, since it is not stored in header
        let mut offsets: Vec<usize> = Vec::new();
        let mut curr_offset = 0;
        for (i, item) in header.payload_entries.iter().enumerate() {
            debug!("entry #{} ({}) offset: {}", i, item.name(), curr_offset);
            offsets.push(curr_offset);
            curr_offset += item.size as usize;
        }

        debug!("key id: {}", header.file_infos[0]);
        let (aes_key, aes_iv) = match header.file_infos[0] {    //t update key system
            3 => (V3_KEY, V3_IV),
            2 => (V2_KEY, V2_IV),
            _ => return Err("unsupported key id".into())
        };

        //read encrypted data, it needs to be decrypted at this stage because of CBC and non aligned
        reader.seek(SeekFrom::Start(header.data_start_offset.into()))?;

        let mut encrypted_data = Vec::with_capacity(header.data_size as usize);
            if header.chunk_count == 0 {    //not chunked, read all data
            encrypted_data = common::read_exact(&mut reader, header.data_size as usize)?;

        } else {
            let mut buffer = vec![0u8; header.chunk_size as usize];
            let mut remain = header.data_size as usize;

            for _ in 0..header.chunk_count {
                let read_size = remain.min(buffer.len());
                let bytes_read = reader.read(&mut buffer[..read_size])?;
                encrypted_data.extend_from_slice(&buffer[..bytes_read]);
                remain -= bytes_read;

                reader.seek(SeekFrom::Current(header.signature_size.into()))?; // skip signature in each chunk
            }
        }

        info!("- decrypting data...");
        let decrypted_data = decrypt_aes128_cbc_pcks7(&encrypted_data, &aes_key, &aes_iv)?;

        Ok(Box::new(InvincibleImageFile { header, offsets, data: decrypted_data }))
    }
}

struct InvincibleImageFile {
    header: Header,
    offsets: Vec<usize>,
    data: Vec<u8>,
}
impl FormatInstance for InvincibleImageFile {
    fn extract_item(&self, _reader: &mut dyn ReadSeek, idx: usize, buf: &mut dyn WriteSeek) -> Result<(), Box<dyn std::error::Error>> {
        let item = &self.header.payload_entries[idx];
        let offset= self.offsets[idx];
        info!("name: {}, offset: {}, size: {}, start offset: {}", item.name(), offset, item.size, item.start_offset);

        let data = &self.data[offset..offset + item.size as usize];
        
        buf.seek(SeekFrom::Start(item.start_offset.into()))?;
        buf.write_all(&data)?;

        Ok(())
    }
    fn get_file_properties(&self) -> Vec<FileProperty> {
        vec! [
            FileProperty::Name(format!("{} {}", self.header.ver3(), self.header.ver1())),
            FileProperty::DataSize(self.header.data_size as usize),
            FileProperty::ItemCount(self.header.payload_count as usize),
        ]
    }
    fn get_item_properties(&self, idx: usize) -> Vec<ItemProperty> {
        let item = &self.header.payload_entries[idx];
        vec![
            ItemProperty::Name(item.name()),
            ItemProperty::Size(item.size as usize)
        ]
    }
}
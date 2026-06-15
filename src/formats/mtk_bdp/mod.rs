mod include;

use std::io::SeekFrom;

use binrw::BinReaderExt;
use log::{debug, info};

use include::*;
use crate::utils::common;
use crate::formats::{Format, FormatInstance, ReadSeek, WriteSeek, FileProperty, ItemProperty};

pub struct MtkBdpFormat;
impl Format for MtkBdpFormat {
    fn name(&self) -> &str {
        "mtk_bdp"
    }
    fn open(&self, mut reader: &mut dyn ReadSeek) -> Result<Box<dyn FormatInstance>, Box<dyn std::error::Error>> {

        // we cant get the file size in ng2 directly so we need to seek to end and get the position
        reader.seek(std::io::SeekFrom::End(0))?;
        let file_size = reader.stream_position()?;
        
        // I wish there was a better way
        let start_offset = file_size.saturating_sub(file_size / 20);
        debug!("file size: {}, search start offs: {}", file_size, start_offset);

        let mut data = Vec::new();
        reader.seek(SeekFrom::Start(start_offset))?;
        reader.read_to_end(&mut data)?;

        let pitit_offset = if let Some(pos) = find_bytes(&data, &PITIT_MAGIC) {
            start_offset + pos as u64
        } else {
            return Err("PITIT magic not found".into());
        };

        debug!("found PITIT at: {}", pitit_offset);
        reader.seek(SeekFrom::Start(pitit_offset as u64 + 8))?;

        let pitit_check = common::read_exact(&mut reader, 8)?;
        //{UPG_INFO}the upg bin is  %d version(old is 0,new is 1)!\n
        let pitit_ver = if pitit_check == PITIT_MAGIC {0} else {1};

        let mut pit_offset: u64 = 0;
        let mut bit_offset: u64 = 0;

        loop {
            let pitit_pit_entry: PITITPITEntry = reader.read_le()?;
            if pitit_pit_entry.nand_size == PITIT_END_MARKER {break}; 
            if pitit_ver == 1 {
                //old PITIT does not have BIT entry, because BIT appears directly after PITIT
                let pitit_bit_entry: PITITBITEntry = reader.read_le()?;
                info!("PITIT Entry - NAND Size: {}, PIT Offset: {}, PIT Size: {}, BIT Offset: {}, BIT Size: {}",
                        pitit_pit_entry.nand_size, pitit_pit_entry.pit_offset, pitit_pit_entry.pit_size, pitit_bit_entry.bit_offset, pitit_bit_entry.bit_size);
                if bit_offset == 0 { bit_offset = pitit_bit_entry.bit_offset as u64 } //use the first entry in PITIT
            } else {
                info!("PITIT Entry - NAND Size: {}, PIT Offset: {}, PIT Size: {}",
                        pitit_pit_entry.nand_size, pitit_pit_entry.pit_offset, pitit_pit_entry.pit_size);
            }
            if pit_offset == 0 { pit_offset = pitit_pit_entry.pit_offset as u64 } //use the first entry in PITIT
        }
        if pitit_ver == 0 && bit_offset == 0{
            //in old upg bin, BIT appears directly after PITIT. so we can use the current file pos cuz we just ended reading PITIT
            bit_offset = reader.stream_position()?;
        }    

        debug!("reading PIT at: {}", pit_offset); //PIT is the NAND partition table.

        reader.seek(SeekFrom::Start(pit_offset))?;
        let mut pit_entries: Vec<PITEntry> = Vec::new();
        let pit_header: PITHeader = reader.read_le()?;
        if pit_header.pit_magic != PIT_MAGIC {
            return Err("invalid PIT magic".into());
        }

        info!("PIT Info - First entry offs: {}, Entry size: {}, Entry count: {}", pit_header.first_entry_offset, pit_header.entry_size, pit_header.entry_count);
        reader.seek(SeekFrom::Start(pit_offset + pit_header.first_entry_offset as u64))?;

        for i in 0..pit_header.entry_count {
            let pit_entry: PITEntry = reader.read_le()?;
            info!("PIT {}. ID: {:02x}, Name: {}, NAND Offset: {}, NAND Size: {}",
                    i + 1, pit_entry.partition_id, pit_entry.name(), pit_entry.offset_on_nand, pit_entry.size_on_nand);
            pit_entries.push(pit_entry);
        }

        debug!("Reading BIT at: {}", bit_offset); //BIT is the table of objects present in the update file.
        reader.seek(SeekFrom::Start(bit_offset))?;
        let mut bit_entries: Vec<BITEntry> = Vec::new();
        let bit_magic = common::read_exact(&mut reader, 20)?;
        if bit_magic != BIT_MAGIC {
            return Err("invalid BIT magic".into());
        }

        let mut bit_i = 0;
        loop {
            let bit_entry: BITEntry = reader.read_le()?;
            if bit_entry.partition_id == BIT_END_MARKER {break};
            info!("BIT {}. ID: {:02x}, Offset: {}, Size: {}, Offset in part: {}",
                    bit_i + 1, bit_entry.partition_id, bit_entry.offset, bit_entry.size, bit_entry.offset_in_target_part);
            bit_entries.push(bit_entry);
            bit_i += 1;
        }

        Ok(Box::new(MtkBdpFile { bit_entries, pit_entries }))
    }
}

struct MtkBdpFile {
    bit_entries: Vec<BITEntry>,
    pit_entries: Vec<PITEntry>,
}
impl FormatInstance for MtkBdpFile {
    fn extract_item(&self, reader: &mut dyn ReadSeek, idx: usize, buf: &mut dyn WriteSeek) -> Result<(), Box<dyn std::error::Error>> {
        let bit_entry = &self.bit_entries[idx];
        let data = common::read_at(reader, bit_entry.offset as u64, bit_entry.size as usize)?;

        buf.seek(SeekFrom::Start(bit_entry.offset_in_target_part as u64))?;
        buf.write_all(&data)?;
        Ok(())
    }
    fn get_file_properties(&self) -> Vec<FileProperty> {
        vec! [
            FileProperty::ItemCount(self.bit_entries.len()),
        ]
    }
    fn get_item_properties(&self, idx: usize) -> Vec<ItemProperty> {
        //find the name of partition using PIT by partition_id. if not found use the ID as placeholder
        let bit_entry = &self.bit_entries[idx];
        let mut name = format!("{:02x}", bit_entry.partition_id);
        for pit_entry in &self.pit_entries {
            if pit_entry.partition_id == bit_entry.partition_id {
                name = pit_entry.name();
            }
        }
        vec![
            ItemProperty::Name(name),
            ItemProperty::Size(bit_entry.size as usize)
        ]
    }
}
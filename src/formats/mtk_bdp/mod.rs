mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Read, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub struct MtkBdpContext {
    pitit_offset: u64,
}

pub fn is_mtk_bdp_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let mut file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};
    let file_size = file.metadata()?.len();
    let mut data = Vec::new();

    // I wish there was a better way
    let start_offset = file_size.saturating_sub(file_size / 20);
    let _ = file.seek(SeekFrom::Start(start_offset));

    file.read_to_end(&mut data)?;

    if let Some(pos) = find_bytes(&data, &PITIT_MAGIC) {
        Ok(Some(Box::new(MtkBdpContext {pitit_offset: start_offset + pos as u64})))
    } else {
        Ok(None)
    }
}

pub fn extract_mtk_bdp(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<MtkBdpContext>().expect("Missing context");

    let offset = ctx.pitit_offset;
    println!("\nReading PITIT at: {}", offset);

    file.seek(SeekFrom::Start(offset + 8))?;

    let pitit_check = common::read_exact(&mut file, 8)?;
    //{UPG_INFO}the upg bin is  %d version(old is 0,new is 1)!\n
    let pitit_ver = if pitit_check == PITIT_MAGIC {0} else {1};

    let mut pit_offset: u64 = 0;
    let mut bit_offset: u64 = 0;
    loop {
        let pitit_pit_entry: PITITPITEntry = file.read_le()?;
        if pitit_pit_entry.nand_size == PITIT_END_MARKER {break}; 
        if pitit_ver == 1 {
            //old PITIT does not have BIT entry, because BIT appears directly after PITIT
            let pitit_bit_entry: PITITBITEntry = file.read_le()?;
            println!("PITIT Entry - NAND Size: {}, PIT Offset: {}, PIT Size: {}, BIT Offset: {}, BIT Size: {}",
                    pitit_pit_entry.nand_size, pitit_pit_entry.pit_offset, pitit_pit_entry.pit_size, pitit_bit_entry.bit_offset, pitit_bit_entry.bit_size);
            if bit_offset == 0 { bit_offset = pitit_bit_entry.bit_offset as u64 } //use the first entry in PITIT
        } else {
            println!("PITIT Entry - NAND Size: {}, PIT Offset: {}, PIT Size: {}",
                    pitit_pit_entry.nand_size, pitit_pit_entry.pit_offset, pitit_pit_entry.pit_size);
        }
        if pit_offset == 0 { pit_offset = pitit_pit_entry.pit_offset as u64 } //use the first entry in PITIT
    }
    if pitit_ver == 0 && bit_offset == 0{
        //in old upg bin, BIT appears directly after PITIT. so we can use the current file pos cuz we just ended reading PITIT
        bit_offset = file.stream_position()?;
    }

    println!("\nReading PIT at: {}", pit_offset); //PIT is the NAND partition table.
    file.seek(SeekFrom::Start(pit_offset))?;
    let mut pit_entries: Vec<PITEntry> = Vec::new();
    let pit_header: PITHeader = file.read_le()?;
    if pit_header.pit_magic != PIT_MAGIC {
        println!("Invalid PIT Magic!");
        return Ok(());
    }
    println!("PIT Info - First entry offs: {}, Entry size: {}, Entry count: {}", pit_header.first_entry_offset, pit_header.entry_size, pit_header.entry_count);
    file.seek(SeekFrom::Start(pit_offset + pit_header.first_entry_offset as u64))?;

    for i in 0..pit_header.entry_count {
        let pit_entry: PITEntry = file.read_le()?;
        println!("{}. ID: {:02x}, Name: {}, NAND Offset: {}, NAND Size: {}",
                i + 1, pit_entry.partition_id, pit_entry.name(), pit_entry.offset_on_nand, pit_entry.size_on_nand);
        pit_entries.push(pit_entry);
    }

    println!("\nReading BIT at: {}", bit_offset); //BIT is the table of objects present in the update file.
    file.seek(SeekFrom::Start(bit_offset))?;
    let mut bit_entries: Vec<BITEntry> = Vec::new();
    let bit_magic = common::read_exact(&mut file, 20)?;
    if bit_magic != BIT_MAGIC {
        println!("Invalid BIT Magic!");
        return Ok(());
    }

    let mut bit_i = 0;
    loop {
        let bit_entry: BITEntry = file.read_le()?;
        if bit_entry.partition_id == BIT_END_MARKER {break};
        println!("{}. ID: {:02x}, Offset: {}, Size: {}, Offset in part: {}",
                bit_i + 1, bit_entry.partition_id, bit_entry.offset, bit_entry.size, bit_entry.offset_in_target_part);
        bit_entries.push(bit_entry);
        bit_i += 1;
    }

    //extraction logic
    for (i, bit_entry) in bit_entries.iter().enumerate() {
        //find the name of partition using PIT by partition_id. if not found use the ID as placeholder
        let mut name = format!("unknown_{:02x}", bit_entry.partition_id);
        for pit_entry in &pit_entries {
            if pit_entry.partition_id == bit_entry.partition_id {
                name = pit_entry.name();
            }
        }

        println!("\n({}/{}) - {}, Offset: {}, Size: {}, Offset in partition: {}",
                i + 1, bit_entries.len(), name, bit_entry.offset, bit_entry.size, bit_entry.offset_in_target_part);

        let data = common::read_file(&file, bit_entry.offset as u64, bit_entry.size as usize)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", name));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
        out_file.seek(SeekFrom::Start(bit_entry.offset_in_target_part as u64))?;
        out_file.write_all(&data)?;

        println!("-- Saved file!");
    }

    println!("\nExtraction finished!");

    Ok(())
}
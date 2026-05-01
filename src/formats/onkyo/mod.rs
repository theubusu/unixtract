mod include;
mod crypto;
use std::any::Any;
use crate::AppContext;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;
use crypto::*;

struct OnkyoCtx {
    header_size: u32,
}

pub fn is_onkyo_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let enc_inihdr = common::read_file(&file, 0, 20)?;
    let dec_inihdr= ub_encrypte_block(&enc_inihdr, &HEADER_KEY);

    if dec_inihdr.starts_with(ONKYO_MAGIC) {
        let header_size = u32::from_le_bytes(dec_inihdr[16..20].try_into().unwrap());
        Ok(Some(Box::new(OnkyoCtx {header_size})))
    } else {
        Ok(None)
    }
}

pub fn extract_onkyo(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<OnkyoCtx>().expect("Missing context");

    println!("Header size: {}", ctx.header_size);

    let enc_hdr = common::read_exact(&mut file, ctx.header_size as usize)?;
    let dec_hdr = ub_encrypte_block(&enc_hdr, &HEADER_KEY);
    opt_dump_dec_hdr(app_ctx, &dec_hdr, "header")?;
    let mut hdr_rdr = Cursor::new(dec_hdr);

    let hdr: Header = hdr_rdr.read_le()?;

    //read info section
    hdr_rdr.seek(SeekFrom::Start(hdr.pack_info_offset as u64))?;
    let info: PackInfo = hdr_rdr.read_le()?;
    println!("Info -\nPackage ID: {}\nVersion: {}\nEntry count: {}\nEntries in file: {}\nPack: {}/{}",
            info.package_id(), info.package_version(), info.entry_count, info.entries_in_file, info.pack_id, info.pack_count,);

    if info.entries_in_file == 0 {
        return Err("There is nothing to extract in this pack".into())   //should this be an error?
    }

    //..."IDsVersions" section
    hdr_rdr.seek(SeekFrom::Start(hdr.ids_versions_offset as u64))?;
    let mut entries: Vec<IDsVersionsEntry> = Vec::new();
    for _ in 0..info.entry_count {
        let entry: IDsVersionsEntry = hdr_rdr.read_le()?;
        entries.push(entry);
    }

    //...table section
    hdr_rdr.seek(SeekFrom::Start(hdr.table_offset as u64))?;
    let mut data_entries: Vec<TableEntry> = Vec::new();
    for _ in 0..info.entry_count {
        let entry: TableEntry = hdr_rdr.read_le()?;
        data_entries.push(entry);
    }

    //
    let mut act_ei = 0;
    for (i, entry) in entries.iter().enumerate() {
        let data_entry = &data_entries[i];

        if entry.pack_location == 0 || (data_entry.offset == 0 && data_entry.checksum == 0){
            continue;
        }

        act_ei += 1;
        println!("\n({}/{}) - {}, Size: {}, Offset: {}, Pack location: {}",
                act_ei, info.entries_in_file, entry.id(), data_entry.size, data_entry.offset, entry.pack_location);

        let data = common::read_file(&mut file, data_entry.offset as u64, data_entry.size as usize)?;
        let mut out_data;

        // -- try to decrypt --
        let mut dec_key: Option<[u8; 8]> = None;
        let mut is_pack = false;

        //try using standard data key
        if ub_encrypte_block(&data[..16], &DATA_KEY).starts_with(ONKYO_MAGIC) {
            dec_key = Some(DATA_KEY);

        //try header key, if success it means this is a package inside a package, and it should not be decrypted
        } else if ub_encrypte_block(&data[..16], &HEADER_KEY).starts_with(ONKYO_MAGIC) { 
            is_pack = true;

        //if not matched with data key, try to calc key
        } else {
            let calced_key = calc_key(&data[..8]); 

            if ub_encrypte_block(&data[..16], &calced_key).starts_with(ONKYO_MAGIC) {  
                dec_key = Some(calced_key);
            }
        }

        if let Some(key) = dec_key {
            println!("- Detected encrypted data, decrypting...");
            out_data = ub_encrypte_block(&data, &key);
            out_data.drain(0..16);      //remove ONKYO Encryption heading

        } else if is_pack {
            println!("- Inner pack detected!");     //maybe handle this...
            out_data = data;

        } else {
            println!("- Failed to decrypt data or entry is not encrypted, saving raw data...");
            out_data = data;
        }

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}_{}.bin", act_ei, entry.id()));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;        
        out_file.write_all(&out_data)?;

        println!("-- Saved file!");

    }

    Ok(())
}
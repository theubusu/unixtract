mod include;
use std::any::Any;
use crate::AppContext;
use crate::utils::aes::decrypt_aes128_cbc_nopad;
use crate::utils::global::opt_dump_dec_hdr;

use std::path::Path;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_utv_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let header_signature = common::read_file(&file, 0, 16)?;
    if header_signature == CLEAR_HEADER_SIGNATURE {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_utv(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let ini_hdr: ClearHeader = file.read_le()?;
    if ini_hdr.clear_header_version != 1 {
        return Err("module clear header is wrong version".into());
    }
    if ini_hdr.key_header_version != 1 {
        return Err("module key header is wrong version".into());
    }
    if ini_hdr.key_header_type != 3 {   //0=plain header, 1=rejected, 2=rsa, 3=rsa(alt)
        return Err("module key header is wrong type".into());
    }

    println!("File info -\nOUI: {:06X}\nMG: {:04X}", ini_hdr.oui, ini_hdr.mg);

    //find key (we could probably match by OUI+MG, but this is better)
    let ini_keyhdr = common::read_exact(&mut file, 256)?;
    let mut dec_keyheader: Option<Vec<u8>> = None;
    for (name, keys) in app_ctx.keys.get_collection("UTV")? {
        let dec = decrypt_key_header(&ini_keyhdr, keys.first().unwrap());
        if dec.ends_with(CLEAR_HEADER_SIGNATURE) {
            println!("\nUsing key: {}", name);
            dec_keyheader = Some(dec);
            break
        }
    }
    let ini_keyhdr = if let Some(_dec_keyheader) = dec_keyheader {
        _dec_keyheader
    } else {
        return Err("No matching key found!".into());
    };

    let ini_keyhdr: KeyHeader = Cursor::new(&ini_keyhdr[0xA0..]).read_le()?;
    if ini_keyhdr.cipher_type != 1 {  //1 = AES, 0=some 64bit cipher
        return Err("unsupported encryption type".into());
    }

    //component ditectory is first module
    let mut comp_dir = common::read_exact(&mut file, ini_hdr.module_size as usize - 32 - 256)?;
    comp_dir = decrypt_aes128_cbc_nopad(&comp_dir, &ini_keyhdr.key, &[0u8;16])?;
    if !comp_dir.ends_with(DECRYPTION_TRAILER) {
        return Err("decryption trailer bytes are missing or too small".into());
    }
    comp_dir.truncate(ini_keyhdr.plaintext_length as usize);

    opt_dump_dec_hdr(app_ctx, &comp_dir, "comp_dir")?;
    let mut comp_dir_rdr = Cursor::new(&comp_dir);  //OK?

    let comp_dir_hdr: ComponentDirectoryHeader = comp_dir_rdr.read_le()?;
    if &comp_dir_hdr.signature != COMP_DIR_SIGNATURE {
        return Err("bad component directory signature".into());
    }
    comp_dir_rdr.seek(SeekFrom::Start(56 + comp_dir_hdr.string_table_size as u64))?;

    for i in 0..comp_dir_hdr.component_count {
        let component: ComponentDescriptor = comp_dir_rdr.read_le()?;
        let component_name = common::string_from_bytes(&comp_dir[component.name_offset as usize..]);

        println!("\n({}/{}) - {}, Version: {:x}, Size: {}, Module count: {}",
                i+1, comp_dir_hdr.component_count, component_name, component.module_version, component.size, component.module_count);

        let output_path = Path::new(&app_ctx.output_dir).join(component_name);
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(output_path)?;

        for (mi, module) in component.modules.iter().enumerate() {
            println!("   module {}/{}, offset: {}, size: {}", mi+1, component.module_count, module.offset, module.module_size);
            file.seek(SeekFrom::Start(module.offset as u64))?;

            let clear_hdr: ClearHeader = file.read_le()?;
            if &clear_hdr.signature != CLEAR_HEADER_SIGNATURE {
                return Err("bad clear header signature".into());
            }

            //each module has its own key header, but as long as the OUI and MG match the initialized ones, the key will be the same as the initialized one.
            //  this is done by the updatetv lib and called the "FAST DECRYPT" path; the key header is not decrypted and the data from component dir is used (~patched in place the init keyheader)
            //  i dont think there should be a case where two modules in same UTV have different oui/mg, so "FULL DECRYPT" case will be ignored. (unless im proven wrong)
            if clear_hdr.oui != ini_hdr.oui || clear_hdr.mg != ini_hdr.mg {
                return Err("OUI/MG mismatch in module".into());
            }
            let _key_header = common::read_exact(&mut file, 256)?;

            let mut data = common::read_exact(&mut file, clear_hdr.module_size as usize - 32 - 256)?;
            data = decrypt_aes128_cbc_nopad(&data, &ini_keyhdr.key, &[0u8;16])?;
            if !data.ends_with(DECRYPTION_TRAILER) {
                return Err("decryption trailer bytes are missing or too small".into());
            }
            data.truncate(module.plaintext_size as usize);

            let mut data_reader = Cursor::new(data);
            let module_header: ModuleHeader = data_reader.read_le()?;
            if &module_header.signature != MOD_HDR_SIGNATURE {
                return Err("bad module header signature".into());
            }
            if module_header.module_index as usize != mi {
                return Err("module index mismatch".into());
            }

            data_reader.seek(SeekFrom::Start(module_header.header_size as u64))?;
            let module_data = common::read_exact(&mut data_reader, module_header.module_size as usize)?;

            out_file.seek(SeekFrom::Start(module_header.module_offset as u64))?;
            out_file.write_all(&module_data)?;

        }

    }

    Ok(())
}
mod include;
use std::any::Any;
use crate::{AppContext, InputTarget};

use std::path::Path;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Seek, SeekFrom};

use crate::utils::common;
use crate::formats::mstar_secure_old::{is_mstar_secure_old_file, extract_mstar_secure_old};
use include::*;

struct FunaiMstarCtx {
    data_offset: u64,
    info_str: String,
}

pub fn is_funai_mstar_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let mut info = common::read_file(&file, 0, 0x1000)?; //try at start of file
    if info.starts_with(b"#@INFO") {
        return Ok(Some(Box::new(FunaiMstarCtx {data_offset: 0x1000, info_str: common::string_from_bytes(&info)})))
    }

    //try at end of file (variant 2)
    let file_size = file.metadata()?.len();
    if file_size < 0x1000 {
        return Ok(None);
    }
    info = common::read_file(&file, file_size - 0x1000, 0x1000)?;
    if info.starts_with(b"#@INFO") {
        return Ok(Some(Box::new(FunaiMstarCtx {data_offset: 0, info_str: common::string_from_bytes(&info)})))
    } else {
        return Ok(None)
    }
}

pub fn extract_funai_mstar(app_ctx: &AppContext, ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;
    let ctx = ctx.downcast::<FunaiMstarCtx>().expect("Missing context");

    let info = InfoStruct::from_str(ctx.info_str).unwrap();
    println!("File info -\nFile code: {}\nBrand name: {}\nModel name: {}\nSoC Version: {}\nFRC Version: {}",
            info.file_code, info.brand_name, info.model_name, info.soc_version, info.frc_version);

    let payloads: Vec<(&str, usize)> = vec![("SoC", info.soc_size), ("FRC60", info.frc60_size), ("FRC120", info.frc120_size)];

    file.seek(SeekFrom::Start(ctx.data_offset))?;

    let mut p_i = 0;
    for (name, size) in payloads {
        if size == 0 {
            continue
        }
        println!("\n#{} - {}, Size: {}", p_i+1, name, size);

        let data = common::read_exact(&mut file, size)?;

        let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", name));
        fs::create_dir_all(&app_ctx.output_dir)?;
        let mut out_file = OpenOptions::new().write(true).create(true).open(&output_path)?;       
        out_file.write_all(&data)?;

        println!("- Saved file!");

        //extract SoC which (should be) mstar_secure_old, this is just a simple container for that format ( so we will go funai_mstar -> mstar_secure_old -> mstar (DUMB?) )
        if name == "SoC" {
            let r_out_file = File::open(&output_path)?;
            let in_ctx: AppContext = AppContext { 
                input: InputTarget::File(r_out_file), 
                output_dir: app_ctx.output_dir.join("SoC"), 
                options: app_ctx.options.clone() 
            };

            //do check and extarct
            if let Some(result) = is_mstar_secure_old_file(&in_ctx)? {
                println!("- Extracting mstar_secure_old...");
                extract_mstar_secure_old(&in_ctx, result)?;
            };

            p_i += 1;
        }
    }

    Ok(())
}
use std::{fs::{self, OpenOptions}, io::Write, path::Path};

use crate::AppContext;

pub fn opt_dump_dec_hdr(app_ctx: &AppContext, data: &[u8], name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !app_ctx.options.iter().any(|e| e == "dump_dec_hdrs") {
        return Ok(())
    }

    let filename = format!("_{}.bin", name);
    let output_path = Path::new(&app_ctx.output_dir).join(&filename);
    fs::create_dir_all(&app_ctx.output_dir)?;
    
    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
    out_file.write_all(&data)?;
        
    println!("[i] Saved {} to {}", name, filename);

    Ok(())
}
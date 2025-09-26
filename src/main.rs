mod common;
mod formats;

use clap::Parser;
use std::path::{PathBuf};
use std::fs::{File};

#[derive(Parser, Debug)]
struct Args {
    input_target: String,
    output_folder: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("unixtract Firmware extractor v0.0");
    let args = Args::parse();

    let target_path = args.input_target;
    println!("Input target: {}", target_path);

    let output_path = args.output_folder;
    println!("Output folder: {}", output_path);

    let path = PathBuf::from(target_path);
    if path.is_dir() {
        if formats::samsung_old::is_samsung_old_dir(&path) {
            println!("Samsung old firmware dir detected!");
            println!();
            formats::samsung_old::extract_samsung_old(&path, &output_path)?
        } else {
            println!("Input format not recognized!");
        }
    } else {
        let file = File::open(path)?;

        println!();

        if formats::tpv_timg::is_tpv_timg_file(&file) {
            println!("TPV TIMG file detected!");
            println!();
            formats::tpv_timg::extract_tpv_timg(&file, &output_path)?;
        } else if formats::pfl_upg::is_pfl_upg_file(&file) {
            println!("PFL UPG file detected!");
            println!();
            formats::pfl_upg::extract_pfl_upg(&file, &output_path)?;
        } else if formats::mstar::is_mstar_file(&file) {
            println!("Mstar upgrade file detected!");
            println!();
            formats::mstar::extract_mstar(&file, &output_path)?;
        } else {
            println!("Input format not recognized!");
        }
    }

    Ok(())
}

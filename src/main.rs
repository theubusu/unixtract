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
    println!("unixtract Firmware extractor");
    let args = Args::parse();

    let target_path = args.input_target;
    println!("Input target: {}", target_path);

    let output_path = args.output_folder;
    println!("Output folder: {}", output_path);

    let path = PathBuf::from(target_path);
    if path.is_dir() {
        if formats::samsung_old::is_samsung_old_dir(&path) {
            println!("Samsung old firmware dir detected!\n");
            formats::samsung_old::extract_samsung_old(&path, &output_path)?
        } else {
            println!("Input format not recognized!");
        }
    } else {
        let file = File::open(path)?;

        println!();

        if formats::sddl_sec::is_sddl_sec_file(&file) {
            println!("SDDL.SEC file detected!");
            formats::sddl_sec::extract_sddl_sec(&file, &output_path)?;
        } else if formats::msd10::is_msd10_file(&file) {
            println!("MSD10 file detected!");
            formats::msd10::extract_msd10(&file, &output_path)?;
        } else if formats::msd11::is_msd11_file(&file) {
            println!("MSD11 file detected!");
            formats::msd11::extract_msd11(&file, &output_path)?;
        } else if formats::tpv_timg::is_tpv_timg_file(&file) {
            println!("TPV TIMG file detected!");
            formats::tpv_timg::extract_tpv_timg(&file, &output_path)?;
        } else if formats::novatek::is_novatek_file(&file) {
            println!("Novatek file detected!");
            formats::novatek::extract_novatek(&file, &output_path)?;
        } else if formats::epk1::is_epk1_file(&file) {
            println!("EPK1 file detected!");
            formats::epk1::extract_epk1(&file, &output_path)?;
        } else if formats::pfl_upg::is_pfl_upg_file(&file) {
            println!("PFL UPG file detected!");
            formats::pfl_upg::extract_pfl_upg(&file, &output_path)?;
        } else if formats::mstar::is_mstar_file(&file) {
            println!("Mstar upgrade file detected!");
            formats::mstar::extract_mstar(&file, &output_path)?;
        } else {
            println!("Input format not recognized!");
        }
    }

    Ok(())
}

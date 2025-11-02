mod common;
mod formats;
mod keys;
mod utils;

use clap::Parser;
use std::path::{PathBuf};
use std::io::{self};
use std::fs::{self, File};

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

    let output_folder_path = PathBuf::from(&output_path);
    if output_folder_path.exists() {
        if output_folder_path.is_dir() {
            let is_empty = fs::read_dir(&output_folder_path)?.next().is_none();
            if !is_empty {
                println!("\nWarning: Output folder exists and is NOT empty! Files may be overwritten!");
                println!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

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
        } 
        if formats::invincible_image::is_invincible_image_file(&file) {
            println!("INVINCIBLE_IMAGE file detected!");
            formats::invincible_image::extract_invincible_image(&file, &output_path)?;
        } 
        else if formats::msd10::is_msd10_file(&file) {
            println!("MSD10 file detected!");
            formats::msd10::extract_msd10(&file, &output_path)?;
        } 
        else if formats::msd11::is_msd11_file(&file) {
            println!("MSD11 file detected!");
            formats::msd11::extract_msd11(&file, &output_path)?;
        } 
        else if formats::tpv_timg::is_tpv_timg_file(&file) {
            println!("TPV TIMG file detected!");
            formats::tpv_timg::extract_tpv_timg(&file, &output_path)?;
        } 
        else if formats::novatek::is_novatek_file(&file) {
            println!("Novatek file detected!");
            formats::novatek::extract_novatek(&file, &output_path)?;
        } 
        else if formats::slp::is_slp_file(&file) {
            println!("SLP file detected!");
            formats::slp::extract_slp(&file, &output_path)?;
        } 
        else if formats::epk1::is_epk1_file(&file) {
            println!("EPK1 file detected!");
            formats::epk1::extract_epk1(&file, &output_path)?;
        }
        //epk2 with unencrypted header
        else if formats::epk2::is_epk2_file(&file) {
            println!("EPK2 file detected!");
            formats::epk2::extract_epk2(&file, &output_path)?;
        }
        //epk with encrypted header - it can be epk2 or epk3 so we need to check
        else if formats::epk::is_epk_file(&file) {
            println!("EPK file detected!");
            formats::epk::extract_epk(&file, &output_path)?;
        }
        else if formats::ruf::is_ruf_file(&file) {
            println!("RUF file detected!");
            formats::ruf::extract_ruf(&file, &output_path)?;
        }
        else if formats::pfl_upg::is_pfl_upg_file(&file) {
            println!("PFL UPG file detected!");
            formats::pfl_upg::extract_pfl_upg(&file, &output_path)?;
        } 
        else if formats::pup::is_pup_file(&file) {
            println!("PUP file detected!");
            formats::pup::extract_pup(&file, &output_path)?;
        }
        else if formats::sony_bdp::is_sony_bdp_file(&file) {
            println!("Sony BDP file detected!");
            formats::sony_bdp::extract_sony_bdp(&file, &output_path)?;
        }
        else if formats::rvp::is_rvp_file(&file) {
            println!("RVP/MVP file detected!");
            formats::rvp::extract_rvp(&file, &output_path)?;
        }
        else if formats::mstar::is_mstar_file(&file) {
            println!("Mstar upgrade file detected!");
            formats::mstar::extract_mstar(&file, &output_path)?;
        }  
        else if formats::roku::is_roku_file(&file) {
            println!("Roku file detected!");
            formats::roku::extract_roku(&file, &output_path)?;
        }
        else if formats::mtk_pkg::is_mtk_pkg_file(&file) {
            println!("MTK Pkg file detected!");
            formats::mtk_pkg::extract_mtk_pkg(&file, &output_path)?;
        } 
        else if formats::mtk_upgrade_loader::is_mtk_upgrade_loader_file(&file) {
            println!("MTK upgrade_loader file detected!");
            formats::mtk_upgrade_loader::extract_mtk_upgrade_loader(&file, &output_path)?;
        }
        else if formats::mtk_bdp::is_mtk_bdp_file(&file) {
            println!("MTK BDP file detected!");
            formats::mtk_bdp::extract_mtk_bdp(&file, &output_path)?;
        }
        else {
            println!("Input format not recognized!");
        }
    }

    Ok(())
}

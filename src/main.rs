mod formats;
mod keys;
mod utils;

use clap::Parser;
use std::path::{PathBuf};
use std::io::{self};
use std::fs::{self, File};
use crate::formats::{Format, get_registry};

#[derive(Parser, Debug)]
struct Args {
    input_target: String,
    output_directory: Option<String>,
}

pub struct AppContext<'a> {
    pub file: &'a std::fs::File,
    pub output_dir: &'a str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("unixtract Firmware extractor");
    let args = Args::parse();

    let target_path_str = args.input_target;
    println!("Input target: {}", target_path_str);
    let target_path = PathBuf::from(&target_path_str);
    
    let output_path_str = if args.output_directory.is_some() {
        args.output_directory.unwrap()
    } else {
        format!("_{}", target_path.file_name().and_then(|s| s.to_str()).unwrap())
    };
    println!("Output directory: {}\n", output_path_str);
    let output_directory_path = PathBuf::from(&output_path_str);

    if output_directory_path.exists() {
        if output_directory_path.is_dir() {
            let is_empty = fs::read_dir(&output_directory_path)?.next().is_none();
            if !is_empty {
                println!("Warning: Output folder already exists and is NOT empty! Files may be overwritten!");
                println!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

    let file = File::open(target_path)?;
    let app_ctx: AppContext = AppContext { file: &file, output_dir: &output_path_str };

    let formats: Vec<Format> = get_registry();
    for format in formats {
        if let Some(ctx) = (format.detector_func)(&app_ctx)? {
            println!("{} detected!", format.name);
            (format.extractor_func)(&app_ctx, Some(ctx))?;
            return Ok(());
        }
    }

    println!("\nInput format not recognized!");
    Ok(())
}

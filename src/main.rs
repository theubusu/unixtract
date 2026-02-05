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
    output_folder: Option<String>,
}

pub struct ProgramContext<'a> {
    pub file: &'a std::fs::File,
    pub output_dir: &'a str,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("unixtract Firmware extractor");
    let args = Args::parse();

    let target_path = args.input_target;
    println!("Input target: {}", target_path);
    let path = PathBuf::from(target_path);

    let output_path = if args.output_folder.is_some() {
        args.output_folder.unwrap()
    } else {
        format!("_{}", path.file_name().and_then(|s| s.to_str()).unwrap())
    };
    println!("Output folder: {}\n", output_path);

    let output_folder_path = PathBuf::from(&output_path);
    if output_folder_path.exists() {
        if output_folder_path.is_dir() {
            let is_empty = fs::read_dir(&output_folder_path)?.next().is_none();
            if !is_empty {
                println!("Warning: Output folder already exists and is NOT empty! Files may be overwritten!");
                println!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

    let file = File::open(path)?;
    let program_context: ProgramContext = ProgramContext { file: &file, output_dir: &output_path };  
    let formats: Vec<Format> = get_registry();

    for format in formats {
        if let Some(ctx) = (format.detect_func)(&program_context)? {
            println!("{} detected!", format.name);
            (format.run_func)(&program_context, Some(ctx))?;
            return Ok(());
        }
    }

    println!("\nInput format not recognized!");
    Ok(())
}

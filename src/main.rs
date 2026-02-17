mod formats;
mod keys;
mod utils;

use clap::Parser;
use std::path::{PathBuf};
use std::io::{self, Seek, SeekFrom};
use std::fs::{self, File};
use crate::formats::{Format, get_registry};

#[derive(Parser, Debug)]
struct Args {
    input_target: String,
    output_directory: Option<String>,

    ///format specific options
    #[arg(short, long)]
    options: Vec<String>,
}

pub enum InputTarget {
    File(File),
    Directory(PathBuf),
}

pub struct AppContext {
    pub input: InputTarget,
    pub output_dir: PathBuf,
    pub options: Vec<String>,
}
impl AppContext {
    pub fn file(&self) -> Option<&File> {
        match &self.input {
            InputTarget::File(f) => Some(f),
            _ => None,
        }
    }

    pub fn dir(&self) -> Option<&PathBuf> {
        match &self.input {
            InputTarget::Directory(p) => Some(p),
            _ => None,
        }
    }
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
    println!("Output directory: {}", output_path_str);
    let output_directory_path = PathBuf::from(&output_path_str);

    if output_directory_path.exists() {
        if output_directory_path.is_dir() {
            let is_empty = fs::read_dir(&output_directory_path)?.next().is_none();
            if !is_empty {
                println!("\nWarning: Output folder already exists and is NOT empty! Files may be overwritten!");
                println!("Press Enter if you want to continue...");
                io::stdin().read_line(&mut String::new())?;
            }
        }
    }

    let app_ctx;

    if target_path.is_file() {
        let file = File::open(&target_path)?;
        app_ctx = AppContext {
            input: InputTarget::File(file),
            output_dir: output_directory_path,
            options: args.options,
        };
    } else if target_path.is_dir() {
        app_ctx = AppContext {
            input: InputTarget::Directory(target_path),
            output_dir: output_directory_path,
            options: args.options,
        };
    } else {
        return Err("Invalid input path!".into());
    }

    let formats: Vec<Format> = get_registry();
    println!("Loaded {} formats!", formats.len());

    for format in formats {
        if let Some(ctx) = (format.detector_func)(&app_ctx)? {
            println!("\n{} detected!", format.name);

            //reset seek of the file if present
            if let Some(mut file) = app_ctx.file() {
                file.seek(SeekFrom::Start(0))?;
            }

            (format.extractor_func)(&app_ctx, ctx)?;

            //extractor returned with no error
            println!("\nExtraction finished! Saved extracted files to {}", output_path_str);
            return Ok(());
        }
    }

    println!("\nInput format not recognized!");
    Ok(())
}

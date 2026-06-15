use std::{fs::{self, File, OpenOptions}, path::Path};

mod utils;
mod formats;
use log::{debug, error, info, warn};
use formats::{ItemProperty, FileProperty};

use clap::Parser;
#[derive(Parser, Debug)]
struct Args {
    input_file: String,
    output_dir: String,

    ///debug log
    #[arg(short, long)]
    debug: bool,

    ///format specific options
    #[arg(short, long)]
    options: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("unixtract ng2");

    let args = Args::parse();

    //log builder
    let mut log_builder = env_logger::Builder::new();
    if args.debug {       
        log_builder.filter_level(log::LevelFilter::Debug);
        log_builder.format_target(true);
        log_builder.format_level(true);
        //log_builder.format_timestamp_millis();    annoying
        log_builder.format_timestamp(None);
    } else {
        log_builder.filter_level(log::LevelFilter::Info);
        log_builder.format_target(false);
        log_builder.format_level(false);
        log_builder.format_timestamp(None);
    }
    log_builder.init();
       
    let in_file = args.input_file;
    info!("Input file: {}", in_file);
    let mut file = File::open(in_file)?;

    let out_dir = args.output_dir;
    info!("Output dir: {}", out_dir);

    let formats = formats::get_formats();
    info!("Loaded {} formats!", formats.len());

    for format in formats {
        match format.open(&mut file) {
            Ok(open_f) => {
                info!("Opened as {}", format.name());

                let f_props = open_f.get_file_properties();

                if let Some(file_name) = get_prop!(f_props, FileProperty::Name) {
                    info!("File name: {}", file_name);
                }

                let item_count = if let Some(&item_count) = get_prop!(f_props, FileProperty::ItemCount) {
                    item_count
                } else {
                    return Err("Did not get item count from opened file".into());
                };

                debug!("item count = {}", item_count);

                for i in 0..item_count {
                    let i_props = open_f.get_item_properties(i);

                    let path = if let Some(name) = get_prop!(i_props, ItemProperty::Name) {
                        format!("{}.bin", name)
                    } else if let Some(path) = get_prop!(i_props, ItemProperty::Path) {
                        path.to_string()
                    } else {
                        warn!("Item has no name or path, using index as placeholder");
                        format!("{}.bin", i)
                    };

                    info!("item ({}/{}) - {}", i+1, item_count, path);

                    fs::create_dir_all(&out_dir)?;
                    let output_path = Path::new(&out_dir).join(path);
                    let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;

                    open_f.extract_item(&mut file, i, &mut out_file)?;
                    info!("- Saved item!");

                }

                info!("Done.");
                return Ok(());
            }

            Err(e) => {
                debug!("Failed to open as {}: {}", format.name(), e);
            }
        }

    }
    error!("Input format not recogized!");

    Ok(())
}

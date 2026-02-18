use crate::utils::common;
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

pub fn split_main_file(path: &PathBuf, out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut file_size = file.metadata()?.len();
    let output_folder = Path::new(&out_path).join("MAIN");

    let mut args_bytes = common::read_file(&mut file, 0, 0x1000)?;
    let mut has_swup_addon = false;
    if args_bytes.starts_with(b"SWUP_ADDON") {
        has_swup_addon = true;
        let addon_offset = u32::from_le_bytes(args_bytes[12..16].try_into()?);
        file_size = addon_offset as u64;
        args_bytes = common::read_file(&mut file, 16, 0x1000)?;
    }
    let args = common::string_from_bytes(&args_bytes);    

    let mut root: Option<String> = None;
    let mut parts = Vec::<(String, u64)>::new();

    //parse parts
    for line in args.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        //get the root partition, strip /dev/
        if let Some(rest) = line.strip_prefix("root=") {
            let dev = rest.trim();
            if let Some(name) = dev.strip_prefix("/dev/") {
                root = Some(name.to_string());
            }
        }

        //get fmaX=XXXXXk partitions
        if let Some((name, size_part)) = line.split_once('=') {
            if name.starts_with("fma") {
                let size_str = size_part.split(':').next().unwrap().trim();

                if let Some(num) = size_str.strip_suffix('k') {
                    let kb: u64 = num.parse().map_err(|_| format!("Bad size: {}", size_str))?;
                    parts.push((name.to_string(), kb * 1024));
                }
            }
        }
    }

    let root = root.ok_or("Failed to get root partition!")?;
    println!("Root - {}", root);
    let root_index = parts.iter().position(|(n, _s)| n == &root).ok_or("Root partition not found in partition list!")?;

    let mut tsize: u64 = 0;

    //read parts from file
    let start_index = root_index - 1; // root is always the second partition in MAIN, so we start from the previous one.
    for (part_name, part_size) in parts.iter().skip(start_index) {
        if tsize >= file_size {
            break
        }

        println!("- {} - Size: {}", part_name, part_size);
        tsize += part_size;

        let data = common::read_exact(&mut file, *part_size as usize)?;
 
        let output_path = Path::new(&output_folder).join(format!("{}.bin", part_name));
        fs::create_dir_all(&output_folder)?;
        
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;
    }

    //read optional swup addon
    if has_swup_addon {
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        println!("- SWUP_ADDON - Size: {}", data.len());

        let output_path = Path::new(&output_folder).join("SWUP_ADDON.bin");
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;
    }

    Ok(())
}
use crate::utils::common;
use std::{fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}};

pub fn split_peaks_file(path: &PathBuf, out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let output_folder = Path::new(&out_path).join("PEAKS");

    let args_bytes = common::read_file(&mut file, 0, 0x210)?;
    if !args_bytes.starts_with(b"D50 ") {
        println!("- Splitting PEAKS is not supported on this file...");
        return Ok(());
    }
    let args = common::string_from_bytes(&args_bytes[16..]);    

    let mut root: Option<String> = None;
    let mut parts = Vec::<(String, u64, Option<&str>)>::new();

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
                let (size_str, flag) = if let Some((size, flag)) = size_part.split_once(':') {
                    (size.trim(), Some(flag.trim()))
                } else {
                    (size_part.trim(), None)
                };

                if let Some(num) = size_str.strip_suffix('k') {
                    let kb: u64 = num.parse().map_err(|_| format!("Bad size: {}", size_str))?;
                    parts.push((name.to_string(), kb * 1024, flag));
                }

                if let Some(num) = size_str.strip_suffix('M') {
                    let mb: u64 = num.parse().map_err(|_| format!("Bad size: {}", size_str))?;
                    parts.push((name.to_string(), mb * 1048576, flag));
                }
            }
        }
    }

    let root = root.ok_or("Failed to get root partition!")?;
    println!("Root - {}", root);
    let root_index = parts.iter().position(|(n, _s, _f)| n == &root).ok_or("Root partition not found in partition list!")?;

    let mut tsize: u64 = 0;

    //read parts from file
    let start_index = root_index - 1; // root is always the second partition in PEAKS, so we start from the previous one.
    for (part_name, part_size, part_flag) in parts.iter().skip(start_index) {
        if tsize >= file_size {
            break
        }

        println!("- {} - Size: {}{}", part_name, part_size, if let Some(part_flag) = part_flag {format!(", Flag: {}", part_flag)} else {format!("")});

        tsize += part_size;

        let data = common::read_exact(&mut file, *part_size as usize)?;
 
        let output_path = Path::new(&output_folder).join(format!("{}.bin", part_name));
        fs::create_dir_all(&output_folder)?;
        
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;
    }

    Ok(())
}
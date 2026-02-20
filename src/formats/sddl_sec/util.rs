use binrw::{BinReaderExt, Endian};
use crate::utils::common;
use std::{fs::{self, File, OpenOptions}, io::{Cursor, Seek, SeekFrom, Write}, path::{Path, PathBuf}};

use crate::utils::compression::decompress_zlib;

pub fn split_peaks_file(path: &PathBuf, out_path: &PathBuf, do_decomp: bool) -> Result<(), Box<dyn std::error::Error>> {
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

        let output_path = Path::new(&output_folder).join(format!("{}.bin", part_name));
        fs::create_dir_all(&output_folder)?;

        let data = common::read_exact(&mut file, *part_size as usize)?;
        
        if do_decomp && let Some(part_flag) = part_flag && *part_flag == "c" {
            println!("-- Decompressing ...");
            decompress_part_to_file(&data, &output_path)?;
            continue
        }
        
        let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
        out_file.write_all(&data)?;
    }

    Ok(())
}

fn decompress_part_to_file(data: &[u8], out_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = Cursor::new(data);
    let mut out_file = OpenOptions::new().append(true).create(true).open(out_path)?;

    //detect endianness, we can safely assume uncomp size wontbe larger than 4294901760
    let uncomp_chen = common::read_exact(&mut reader, 4)?;
    let endianness = if uncomp_chen[0..2] == *b"\x00\x00" {
        Endian::Little
    } else {
        Endian::Big
    };

    reader.seek(SeekFrom::Start(0))?;
    let uncompressed_size: u32 = reader.read_type(endianness)?;
    let first_blk: u32 = reader.read_type(endianness)?;
    let count_blks = (first_blk - 4) / 4;

    println!("[INFO] Endianness: {}, Uncompressed size: {}, First block loc: {}, Block count: {}", 
            endianness, uncompressed_size, first_blk, count_blks);

    reader.seek(SeekFrom::Start(4))?;

    let mut block_locs: Vec<u32> = Vec::new();

    for _ in 0..count_blks {
        let loc: u32 = reader.read_type(endianness)?;
        block_locs.push(loc);
    }

    for (n, blk) in block_locs.iter().enumerate() {
        reader.seek(SeekFrom::Start(*blk as u64))?;

        print!("\rDecompressing... {}/{}", 
              n + 1, count_blks);
        std::io::stdout().flush()?;

        //special handling for last block since there is no next block to check, just assume 16k
        let blk_size = if n == count_blks as usize - 1 {16384} else {block_locs[n + 1] - blk};

        let compressed = common::read_exact(&mut reader, blk_size as usize)?;
        let decompressed = decompress_zlib(&compressed)?;

        out_file.write_all(&decompressed)?;
    }

    println!();

    Ok(())
}
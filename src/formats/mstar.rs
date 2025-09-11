use std::fs::{File};
use crate::common;

pub fn is_mstar_file(file: &File) -> bool {
    let header = common::read_file(&file, 0, 32768).expect("REASON");
    let header_string = String::from_utf8_lossy(&header);

    if header_string.contains("filepartload") & header_string.contains("MstarUpgrade") | header_string.contains("CtvUpgrade") {
        true
    } else {
        false
    }
}

pub fn extract_mstar(file: &File) {
    println!("extract mstar file");

    let mut script = common::read_file(&file, 0, 32768).expect("REASON");

    if let Some(pos) = script.iter().position(|x| [0x00, 0xFF].contains(x)) {
        script.truncate(pos);
    }

    let script_string = String::from_utf8_lossy(&script);
    //println!("{}", script_string);

    let lines: Vec<&str> = script_string.lines().map(|l| l.trim()).collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("filepartload") {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 5 {
                let offset = parts[3];
                let size = parts[4];

                //try to get partname from comment
                let mut partname = if let Some(idx) = line.find('#') {
                    line[idx + 1..].trim()
                } else {
                    "unknown"
                };

                let mut compression = "none";
                let mut j = i + 1;
                while j < lines.len() && !lines[j].starts_with("filepartload") {
                    //get compression method
                    if lines[j].contains("mscompress7") {
                        compression = "lzma";
                    } else if lines[j].contains("lz4") {
                        compression = "lz4";
                    }

                    // try to get partname from nand/mmc/ubi writes
                    if lines[j].starts_with("mmc write") | lines[j].starts_with("nand write") | lines[j].starts_with("ubi write"){
                        let parts: Vec<&str> = lines[j].split_whitespace().collect();
                        if partname == "unknown" {
                            partname = parts[3]
                        }
                    }

                    // check if its boot partition
                    if lines[j].starts_with("mmc write.boot") {
                        if partname == "unknown" {
                            partname = "boot"
                        }
                    }
                    j += 1;
                }

                println!("offset: {} size: {} --> {} (compression: {})", offset, size, partname, compression);
            }
        }

        i += 1;
    }

}
use std::fs::File;

use crate::common;
use crate::formats;

pub fn is_epk_file(file: &File) -> bool {
    let versions = common::read_file(&file, 1712, 36).expect("Failed to read from file.");

    if check_epk_version(&versions).is_some() {
        true
    } else {
        false
    }
}

fn check_epk_version(versions: &[u8]) -> Option<String> {
    let epk2_pattern = "____XXXX.XXXX.XXXX__XX.XX.XXX_______";
    let epk3_pattern = "____X.X.X___________X.X.X___________";

    if match_with_pattern(&versions, epk2_pattern) {
        Some("epk2".to_string())
    } else if match_with_pattern(&versions, epk3_pattern) {     
        Some("epk3".to_string())
    } else {
        None
    }
}

fn match_with_pattern(data: &[u8], pattern: &str) -> bool {
    for (&b, p) in data.iter().zip(pattern.bytes()) {
        match p {
            b'_' if b != 0x00 => return false,
            b'X' if !b.is_ascii_digit() => return false,
            b'.' if b != b'.' => return false,
            _ if p != b'_' && p != b'X' && p != b'.' => return false,
            _ => {}
        }
    }
    true
}

pub fn extract_epk(file: &File, output_folder: &str) -> Result<(), Box<dyn std::error::Error>> {

    let versions = common::read_file(&file, 1712, 36)?;
    let epk_version = check_epk_version(&versions);
    
    if epk_version == Some("epk2".to_string()) {
        println!("EPK2 detected!\n");
        formats::epk2::extract_epk2(file, output_folder)?;
    } else if epk_version == Some("epk3".to_string()) {
        println!("EPK3 detected! Not supported yet.");
    }

    Ok(())
}
use std::fs::{File};
use std::io::{Read, Seek, SeekFrom};

pub fn read_file(mut file: &File, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; size];
    let _bytes_read = file.read(&mut buffer)?;

    // reset seek (!
    file.seek(SeekFrom::Start(offset))?;
    Ok(buffer)
}
use std::fs::{File};
use std::io::{self, Read, Seek, SeekFrom};

pub fn read_file(mut file: &File, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; size];
    let _bytes_read = file.read(&mut buffer)?;

    // reset seek (!
    file.seek(SeekFrom::Start(offset))?;
    Ok(buffer)
}

pub fn read_exact<R: Read>(reader: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn string_from_bytes(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}
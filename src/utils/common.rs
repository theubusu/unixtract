use std::io::{Read, Seek, SeekFrom};

pub fn read_at<T: Read + Seek + ?Sized>(reader: &mut T, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size];
    reader.read(&mut buf)?;

    //reset seek
    reader.seek(SeekFrom::Start(offset))?;
    Ok(buf)
}

pub fn read_exact<R: Read>(reader: &mut R, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn string_from_bytes(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}
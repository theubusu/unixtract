use std::io::{self, Read, Cursor};

use flate2::read::ZlibDecoder;
use flate2::read::GzDecoder;
use lzma_rs::lzma_decompress;
use lz4::block::decompress;

pub fn decompress_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

pub fn decompress_gzip(compressed_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

pub fn decompress_lzma(compressed_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut input = Cursor::new(compressed_data);
    let mut output = Vec::new();
    
    lzma_decompress(&mut input, &mut output)?;
    Ok(output)
}

pub fn decompress_lz4(compressed_data: &[u8], original_size: i32) -> Result<Vec<u8>, std::io::Error> {
    match decompress(compressed_data, Some(original_size)) {
        Ok(decompressed) => Ok(decompressed),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}
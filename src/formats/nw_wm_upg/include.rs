use std::io::Cursor;

use binrw::BinReaderExt;
use des::{Des};
use ecb::{Decryptor as EcbDecryptor, cipher::{BlockDecryptMut, KeyInit, generic_array::GenericArray}};

use crate::utils::{common, compression::decompress_zlib};

type DesEcbDec = EcbDecryptor<Des>;

pub fn decrypt_des_ecb(key: &[u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buffer = ciphertext.to_vec();
    let mut decryptor = DesEcbDec::new(key.into());
    for chunk in buffer.chunks_exact_mut(8) {
        let block: &mut [u8; 8] = chunk.try_into()?;
        decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
    }
    Ok(buffer)
}

//custom zlib format, extract for convinience

const ZLIB_BLOCK_SIZE: u32 = 0x1000;
pub fn is_compressed_zlib(data: &[u8]) -> bool {
    let chunk1_size = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if chunk1_size > ZLIB_BLOCK_SIZE + 256 /* to be safe */ {return false};
    if chunk1_size + 4 > data.len() as u32 {return false};

    let chunk1 = &data[4..4+ chunk1_size as usize];
    if let Ok(_) = decompress_zlib(&chunk1) {
        return true
    }
    false
}
pub fn decompress_zlib_file(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out_data: Vec<u8> = Vec::new();
    let mut data_reader = Cursor::new(data);
    
    loop {
        if let Ok(chunk_size) = data_reader.read_le::<u32>() {
            if chunk_size == 0 {break};
            let compressed = common::read_exact(&mut data_reader, chunk_size as usize)?;
            let decompressed = decompress_zlib(&compressed)?;
            out_data.extend_from_slice(&decompressed);
        } else {
            break;
        }
    }

    Ok(out_data)
}

pub enum EncryptionMode{
    Des([u8; 8]),
    Aes([u8; 16])
}
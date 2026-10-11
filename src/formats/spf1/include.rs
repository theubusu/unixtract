use binrw::BinRead;

#[derive(BinRead)]
pub struct Spf1Header {
    _magic: [u8;4],     //SPF1
    _header_size: u32,
    pub data_size: u32,
    pub unpacked_size: u32,
    _crc_checksum: u32,
    pub compression_type: u8,
    pub signature_type: u8,
    _reserved: [u8;2],
}


use aes::Aes256;
use aes::cipher::{Block, BlockDecrypt, KeyInit};

pub fn decrypt_aes256_cbc_cts(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const BLOCK: usize = 16;

    let cipher = Aes256::new_from_slice(key).map_err(|_| "Invalid AES key")?;

    let mut output = Vec::with_capacity(data.len());
    let mut previous = *iv;

    let full_blocks = data.len() / BLOCK;
    let remainder = data.len() % BLOCK;

    let normal_blocks = if remainder == 0 {
        full_blocks
    } else {
        full_blocks - 1
    };

    let mut offset = 0;

    //normal CBC decryption
    for _ in 0..normal_blocks {
        let ciphertext = &data[offset..offset + BLOCK];
        let mut block = Block::<Aes256>::clone_from_slice(ciphertext);

        cipher.decrypt_block(&mut block);
        for i in 0..BLOCK {
            output.push(block[i] ^ previous[i]);
        }
        previous.copy_from_slice(ciphertext);
        offset += BLOCK;
    }

    // CBC ciphertext stealing
    if remainder != 0 {
        let final_full = &data[offset..offset + BLOCK];
        let final_partial = &data[offset + BLOCK..];

        let mut intermediate = Block::<Aes256>::clone_from_slice(final_full);
        cipher.decrypt_block(&mut intermediate);

        let mut partial_plaintext = vec![0u8; remainder];
        for i in 0..remainder {
            partial_plaintext[i] = intermediate[i] ^ final_partial[i];
        }

        let mut reconstructed = Block::<Aes256>::default();
        reconstructed[..remainder].copy_from_slice(final_partial);
        reconstructed[remainder..].copy_from_slice(&intermediate[remainder..]);
        cipher.decrypt_block(&mut reconstructed);

        for i in 0..BLOCK {
            output.push(reconstructed[i] ^ previous[i]);
        }
        output.extend_from_slice(&partial_plaintext);
    }

    Ok(output)
}

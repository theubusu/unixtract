//! Newer Onkyo packages: AES-256-CBC around independently encrypted headers/entries.
//! Keys are supplied through UKF, never inferred from a filename or device identity.
use crate::{AppContext, utils::global::opt_dump_dec_hdr};
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
};

type Error = Box<dyn std::error::Error>;
const MAX_HEADER: usize = 1024 * 1024;

#[derive(Clone)]
struct Keys {
    seed: [u8; 32],
    network: [u8; 8],
    id: [u8; 16],
}

pub struct Context {
    keys: Keys,
    wrapped: bool,
    header_size: usize,
}

fn aes_material(seed: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    let selected = [24, 18, 7, 12, 29, 23, 12, 16].map(|i| seed[i]);
    let key = Sha256::digest(selected).into();
    let iv = [0, 31, 27, 29, 2, 15, 7, 16, 14, 9, 11, 18, 12, 8, 4, 22].map(|i| seed[i]);
    (key, iv)
}

fn unwrap_aes(data: &mut [u8], seed: &[u8; 32]) -> Result<(), Error> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err("Onkyo AES input is not a nonempty sequence of complete blocks".into());
    }
    let (key, iv) = aes_material(seed);
    cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(data)
        .map_err(|_| "Onkyo AES decryption failed")?;
    Ok(())
}

/// The newer proprietary XOR stream, with state reset at each package/entry.
fn crypt(data: &[u8], key: &[u8; 8]) -> Vec<u8> {
    let [a, b, c, d, e, f, g, h] = key.map(u32::from);
    let table = [
        ((g << 1) & 255) + (a >> 3),
        (e << 2) + g,
        (c << 3) + (d >> 1),
        ((b << 4) & 255) + (c >> 2),
        a + (h >> 3),
        ((d << 1) & 255) + (f >> 4),
        (f << 2) + e,
        (h << 3) + (b >> 1),
        (c << 4) + (e >> 2),
        e + (d >> 3),
        (a << 1) + (h >> 4),
        a + (d << 2),
        ((f << 3) & 255) + (c >> 1),
        ((b << 4) & 255) + (b >> 2),
        h + (g >> 3),
        ((g << 1) & 255) + f,
    ]
    .map(|v| v as u8);
    let mut state = ((a << 4)
        + (b << 3)
        + (c << 2)
        + ((d << 1) & 255)
        + (e << 4)
        + ((f << 3) & 255)
        + (g << 2)
        + h) as u8;
    data.iter()
        .enumerate()
        .map(|(i, &byte)| {
            let decoded = byte ^ state;
            state = table[i % 16]
                .wrapping_add(table[((i % 208 + 1) * 13) % 16])
                .wrapping_add(((i + 1) >> 6) as u8)
                .wrapping_add(state.rotate_right(1));
            decoded
        })
        .collect()
}

/// Onkyo's rotating word-sum, not a CRC or a cryptographic signature.
fn checksum(data: &[u8]) -> Result<u32, Error> {
    if data.is_empty() || data.len() % 4 != 0 {
        return Err("Invalid Onkyo checksum range".into());
    }
    let mut sum: u32 = 0;
    let mut result = 0;
    for word in data.chunks_exact(4) {
        result = sum.wrapping_add(u32::from_le_bytes(word.try_into()?));
        sum = result.rotate_left(11);
    }
    Ok(result)
}

fn word(data: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = data
        .get(offset..offset.checked_add(4).ok_or("Offset overflow")?)
        .ok_or("Truncated Onkyo header")?;
    Ok(u32::from_le_bytes(bytes.try_into()?))
}

fn header_length(prefix: &[u8], keys: &Keys, file_len: u64) -> Result<Option<usize>, Error> {
    if prefix.len() < 20 {
        return Ok(None);
    }
    let plain = crypt(&prefix[..20], &keys.network);
    if !plain.starts_with(&keys.id) {
        return Ok(None);
    }
    let size = word(&plain, 16)? as usize;
    if !(48..=MAX_HEADER).contains(&size) || size % 16 != 0 || size as u64 > file_len {
        return Err("Invalid newer Onkyo header size".into());
    }
    Ok(Some(size))
}

fn decode_header(data: &[u8], keys: &Keys) -> Result<Vec<u8>, Error> {
    let size = header_length(data, keys, data.len() as u64)?.ok_or("Onkyo identifier mismatch")?;
    let header = crypt(&data[..size], &keys.network);
    if checksum(&header[24..])? != word(&header, 20)? {
        return Err("Newer Onkyo header checksum mismatch".into());
    }
    Ok(header)
}

pub fn detect(app: &AppContext) -> Result<Option<Context>, Error> {
    let Some(mut file) = app.file() else {
        return Ok(None);
    };
    let Ok(profiles) = app.keys.get_collection("ONKYO_NEW_KEYS") else {
        return Ok(None);
    };
    let file_len = file.metadata()?.len();
    if file_len < 32 {
        return Ok(None);
    }
    let mut prefix = [0; 32];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut prefix)?;
    for (_, parts) in profiles {
        if parts.len() != 3 {
            return Err("ONKYO_NEW_KEYS requires seed, network key, identifier".into());
        }
        let keys = Keys {
            seed: parts[0].as_slice().try_into()?,
            network: parts[1].as_slice().try_into()?,
            id: parts[2].as_slice().try_into()?,
        };
        // An extracted nested package has no AES wrapper.
        for wrapped in [false, true] {
            if wrapped && file_len % 16 != 0 {
                continue;
            }
            let mut probe = prefix;
            if wrapped {
                unwrap_aes(&mut probe, &keys.seed)?;
            }
            if let Some(size) = header_length(&probe, &keys, file_len)? {
                let mut header = vec![0; size];
                file.seek(SeekFrom::Start(0))?;
                file.read_exact(&mut header)?;
                if wrapped {
                    unwrap_aes(&mut header, &keys.seed)?;
                }
                decode_header(&header, &keys)?;
                return Ok(Some(Context {
                    keys,
                    wrapped,
                    header_size: size,
                }));
            }
        }
    }
    Ok(None)
}

struct Entry {
    name: String,
    offset: usize,
    size: usize,
    checksum: u32,
}

fn entries(header: &[u8], file_len: usize) -> Result<Vec<Entry>, Error> {
    let info = word(header, 24)? as usize;
    let ids = word(header, 28)? as usize;
    let table = word(header, 32)? as usize;
    let info = header
        .get(info..info.checked_add(40).ok_or("Offset overflow")?)
        .ok_or("Truncated Onkyo package info")?;
    let count = info[36] as usize;
    let pack = info[38];
    let ids = header
        .get(ids..ids.checked_add(count * 8).ok_or("Offset overflow")?)
        .ok_or("Truncated Onkyo ID table")?;
    let table = header
        .get(table..table.checked_add(count * 16).ok_or("Offset overflow")?)
        .ok_or("Truncated Onkyo entry table")?;
    let mut entries = Vec::new();
    for i in 0..count {
        let id = &ids[i * 8..i * 8 + 8];
        let offset = word(table, i * 16 + 4)? as usize;
        let expected = word(table, i * 16 + 8)?;
        if id[0] == 0 || (offset == 0 && expected == 0) {
            continue;
        }
        if id[0] != pack {
            return Err("Onkyo entry belongs to a different package".into());
        }
        let size = word(table, i * 16)? as usize;
        if offset < header.len()
            || size < 16
            || size % 4 != 0
            || offset.checked_add(size).ok_or("Entry range overflow")? > file_len
        {
            return Err("Invalid Onkyo payload range".into());
        }
        let end = id[1..].iter().position(|&b| b == 0).unwrap_or(7);
        let name = std::str::from_utf8(&id[1..1 + end])?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("Invalid Onkyo entry name".into());
        }
        entries.push(Entry {
            name: name.into(),
            offset,
            size,
            checksum: expected,
        });
    }
    if entries.len() != info[39] as usize {
        return Err("Onkyo entry count mismatch".into());
    }
    Ok(entries)
}

pub fn extract(app: &AppContext, ctx: Context) -> Result<(), Error> {
    let mut file = app.file().ok_or("Expected Onkyo file")?;
    file.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    if ctx.wrapped {
        unwrap_aes(&mut data, &ctx.keys.seed)?;
    }
    let header = decode_header(&data[..ctx.header_size], &ctx.keys)?;
    let entries = entries(&header, data.len())?;
    // Validate every payload before emitting any extracted files.
    for entry in &entries {
        if checksum(&data[entry.offset..entry.offset + entry.size])? != entry.checksum {
            return Err(format!("Onkyo payload checksum mismatch: {}", entry.name).into());
        }
    }
    opt_dump_dec_hdr(app, &header, "header")?;
    if entries.is_empty() {
        println!("Metadata-only Onkyo package; nothing to extract.");
    }
    for (i, entry) in entries.iter().enumerate() {
        let payload = &data[entry.offset..entry.offset + entry.size];
        let decoded;
        let output = if header_length(payload, &ctx.keys, payload.len() as u64)
            .ok()
            .flatten()
            .is_some()
            && decode_header(payload, &ctx.keys).is_ok()
        {
            println!(
                "{}: nested package (run unixtract on this output with the same key file)",
                entry.name
            );
            payload
        } else if crypt(&payload[..16], &ctx.keys.network) == ctx.keys.id {
            decoded = crypt(payload, &ctx.keys.network);
            &decoded[16..]
        } else {
            println!(
                "{}: unrecognized payload encoding; preserving raw bytes",
                entry.name
            );
            payload
        };
        fs::create_dir_all(&app.output_dir)?;
        fs::write(
            app.output_dir.join(format!("{}_{}.bin", i + 1, entry.name)),
            output,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

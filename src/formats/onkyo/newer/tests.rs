use super::*;
use crate::{InputTarget, ukf::KeySystem};
use aes::cipher::BlockEncryptMut;
use std::{
    fs::File,
    sync::atomic::{AtomicU64, Ordering},
};

fn keys() -> Keys {
    Keys {
        seed: std::array::from_fn(|i| i as u8),
        network: [0, 1, 2, 3, 4, 5, 6, 7],
        id: *b"SyntheticTestID!",
    }
}

fn put(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn package(payload: Option<&[u8]>) -> Vec<u8> {
    let k = keys();
    let mut h = vec![0; 512];
    h[..16].copy_from_slice(&k.id);
    put(&mut h, 16, 512);
    put(&mut h, 24, 48);
    put(&mut h, 28, 96);
    put(&mut h, 32, 160);
    h[48..57].copy_from_slice(b"SYNTHETIC");
    h[84] = 1;
    h[85] = 1;
    h[86] = 1;
    if let Some(p) = payload {
        h[87] = 1;
        h[96] = 1;
        h[97..102].copy_from_slice(b"TEST1");
        put(&mut h, 160, p.len() as u32);
        put(&mut h, 164, 512);
        put(&mut h, 168, checksum(p).unwrap());
    }
    let sum = checksum(&h[24..]).unwrap();
    put(&mut h, 20, sum);
    let mut result = crypt(&h, &k.network);
    if let Some(p) = payload {
        result.extend_from_slice(p);
    }
    result
}

fn wrap(mut data: Vec<u8>) -> Vec<u8> {
    // The real format's trailer is opaque: test non-PKCS padding, too.
    data.extend_from_slice(&[0xa5; 32]);
    let len = data.len();
    let (key, iv) = aes_material(&keys().seed);
    cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut data, len)
        .unwrap();
    data
}

static COUNTER: AtomicU64 = AtomicU64::new(0);
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "unixtract-onkyo-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(data: &[u8], scratch: &Scratch) -> Result<(), Error> {
    let k = keys();
    let key_text = format!(
        "collection \"ONKYO_NEW_KEYS\": {{ \"test\": {{ x\"{}\", x\"{}\", x\"{}\" }} }}",
        hex::encode(k.seed),
        hex::encode(k.network),
        hex::encode(k.id)
    );
    let ks = KeySystem::init(&key_text)?;
    let input = scratch.0.join("input.bin");
    fs::write(&input, data)?;
    let options = vec![];
    let app = AppContext {
        input: InputTarget::File(File::open(input)?),
        output_dir: scratch.0.join("out"),
        options: &options,
        keys: &ks,
    };
    let ctx = super::super::is_onkyo_file(&app)?.ok_or("not recognized")?;
    super::super::extract_onkyo(&app, ctx)
}

#[test]
fn independent_cipher_and_derivation_vectors() {
    // Synthetic vectors produced independently by the Python decoder, spanning
    // the 16/64/208-byte state boundaries. No vendor bytes or keys are embedded.
    let data: Vec<u8> = (0..512).map(|i| i as u8).collect();
    let output = crypt(&data, &keys().network);
    assert_eq!(
        hex::encode(Sha256::digest(&output)),
        "2003f5e0a15dc44aa628b2816bfc99cbe437d6f711821f21130d7c4f2800b023"
    );
    assert_eq!(crypt(&output, &keys().network), data);
    assert_eq!(
        hex::encode(aes_material(&keys().seed).0),
        "b0f9eff226c7dea0a8e67aef55251b367e06435c1678b2cde0171a1ccfe7bd99"
    );
}

#[test]
fn aes_wrapped_and_unwrapped_payloads() {
    let clear = [keys().id.as_slice(), b"0123456789abcdef"].concat();
    let pack = package(Some(&crypt(&clear, &keys().network)));
    for input in [pack.clone(), wrap(pack)] {
        let s = Scratch::new();
        run(&input, &s).unwrap();
        assert_eq!(
            fs::read(s.0.join("out/1_TEST1.bin")).unwrap(),
            b"0123456789abcdef"
        );
    }
}

#[test]
fn preserve_nested_package_and_reset_its_cipher() {
    let inner = package(Some(&crypt(
        &[keys().id.as_slice(), &[7; 32]].concat(),
        &keys().network,
    )));
    let outer = wrap(package(Some(&inner)));
    let s = Scratch::new();
    run(&outer, &s).unwrap();
    let extracted = fs::read(s.0.join("out/1_TEST1.bin")).unwrap();
    assert_eq!(extracted, inner);
    let next = Scratch::new();
    run(&extracted, &next).unwrap();
    assert_eq!(fs::read(next.0.join("out/1_TEST1.bin")).unwrap(), [7; 32]);
}

#[test]
fn metadata_only_and_corruption() {
    let s = Scratch::new();
    run(&wrap(package(None)), &s).unwrap();
    assert!(!s.0.join("out").exists());
    let mut pack = package(Some(&crypt(
        &[keys().id.as_slice(), &[9; 16]].concat(),
        &keys().network,
    )));
    pack[520] ^= 1;
    let s = Scratch::new();
    assert!(
        run(&pack, &s)
            .unwrap_err()
            .to_string()
            .contains("payload checksum")
    );
    assert!(!s.0.join("out").exists());
    let mut pack = package(None);
    pack[40] ^= 1;
    assert!(
        run(&pack, &Scratch::new())
            .unwrap_err()
            .to_string()
            .contains("header checksum")
    );
}

#[test]
fn reject_invalid_ranges_and_names() {
    let pack = package(Some(&crypt(
        &[keys().id.as_slice(), &[0; 16]].concat(),
        &keys().network,
    )));
    let mut h = decode_header(&pack, &keys()).unwrap();
    put(&mut h, 164, u32::MAX);
    assert!(entries(&h, pack.len()).is_err());
    put(&mut h, 164, 512);
    h[97] = b'/';
    assert!(entries(&h, pack.len()).is_err());
    h[97] = b'T';
    put(&mut h, 32, u32::MAX);
    assert!(entries(&h, pack.len()).is_err());
    assert!(unwrap_aes(&mut [0; 17], &keys().seed).is_err());
    assert!(header_length(&[0; 8], &keys(), 8).unwrap().is_none());
}

#[test]
fn preserves_unrecognized_payload_encoding() {
    let payload = [0x5a; 32];
    let s = Scratch::new();
    run(&wrap(package(Some(&payload))), &s).unwrap();
    assert_eq!(fs::read(s.0.join("out/1_TEST1.bin")).unwrap(), payload);
}

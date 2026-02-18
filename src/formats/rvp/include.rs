pub fn decrypt_xor(data: &[u8]) -> Vec<u8> {
    let key_bytes = b"\xCC\xF0\xC8\xC4\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA\xC6\xCA\xCC\xDA";
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
        .collect()
}
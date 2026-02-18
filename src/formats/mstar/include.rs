pub fn parse_number(s: &str) -> Option<u64> {
    if let Some(hex_str) = s.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16).ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}
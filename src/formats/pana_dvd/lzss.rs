pub fn decompress_lzss(data: &[u8]) -> Vec<u8> {
    let mut window = [0u8; 0x1000];
    let mut dst = Vec::new();
    let mut src_i = 0;
    let mut win_pos = 0xFEE;
    let mut flags = 0u16;

    while src_i < data.len() {
        flags >>= 1;
        if (flags & 0x100) == 0 {
            if src_i >= data.len() {
                break;
            }
            flags = data[src_i] as u16 | 0xFF00;
            src_i += 1;
        }

        if (flags & 1) == 0 {
            // Backreference
            if src_i + 1 >= data.len() {
                break;
            }
            let b1 = data[src_i];
            let b2 = data[src_i + 1];
            src_i += 2;

            let mut offset = (b1 as usize) | (((b2 & 0xF0) as usize) << 4);
            let length = ((b2 & 0x0F) as usize) + 3;

            for _ in 0..length {
                let c = window[offset];
                dst.push(c);
                window[win_pos] = c;
                win_pos = (win_pos + 1) & 0xFFF;
                offset = (offset + 1) & 0xFFF;
            }
        } else {
            // Literal
            if src_i >= data.len() {
                break;
            }
            let c = data[src_i];
            src_i += 1;
            dst.push(c);
            window[win_pos] = c;
            win_pos = (win_pos + 1) & 0xFFF;
        }
    }

    dst
}
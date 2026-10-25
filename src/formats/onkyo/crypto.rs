use super::include::ONKYO_MAGIC;

pub fn ub_encrypte_block(input: &[u8], key: &[u8; 8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let state_counter = 0;
    let state_byte = 0;

    let mut u_var3: u8 = if state_counter == 0 {
        key[0]
    } else {
        state_byte
    };

    let mut u_var4: u32 = (state_counter % 7) + 1;
    let mut u_var7: u32 = state_counter;

    for &byte in input {
        output.push(u_var3 ^ byte);

        let pb_var1 = key[u_var4 as usize];
        u_var7 = u_var7.wrapping_add(1);

        if (u_var4 + 1) * 0x10000 < 0x70001 {
            u_var4 = (u_var4 + 1) & 0xFFFF;
        } else {
            u_var4 = 1;
        }

        let rot = ((u_var3 >> 7) | ((u_var3 & 0x7F) << 1)) & 0xFF;

        u_var3 = pb_var1
            .wrapping_add(rot)
            .wrapping_add((u_var7 >> 6) as u8);
    }

    output
}

pub fn calc_key(ciphertext: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];

    let mut ks = ONKYO_MAGIC[0] ^ ciphertext[0];
    key[0] = ks;

    for j in 1..8 {
        let rol = (ks >> 7) | ((ks & 0x7f) << 1);
        ks = ONKYO_MAGIC[j] ^ ciphertext[j];

        key[j] = ks.wrapping_sub(rol);
    }

    key
}

//newer scheme
pub fn crypt_new(data: &[u8], key: &[u8; 8]) -> Vec<u8> {
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
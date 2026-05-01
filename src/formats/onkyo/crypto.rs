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
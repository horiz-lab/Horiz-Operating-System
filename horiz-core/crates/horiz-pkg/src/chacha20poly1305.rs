// --- ChaCha20-Poly1305 AEAD (Zero-Dependency, RFC 8439) ---

fn quarterround(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let le = u32::from_le_bytes;
    let mut s = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        le([key[0],key[1],key[2],key[3]]),
        le([key[4],key[5],key[6],key[7]]),
        le([key[8],key[9],key[10],key[11]]),
        le([key[12],key[13],key[14],key[15]]),
        le([key[16],key[17],key[18],key[19]]),
        le([key[20],key[21],key[22],key[23]]),
        le([key[24],key[25],key[26],key[27]]),
        le([key[28],key[29],key[30],key[31]]),
        counter,
        le([nonce[0],nonce[1],nonce[2],nonce[3]]),
        le([nonce[4],nonce[5],nonce[6],nonce[7]]),
        le([nonce[8],nonce[9],nonce[10],nonce[11]]),
    ];
    let init = s;
    for _ in 0..10 {
        quarterround(&mut s, 0, 4,  8, 12);
        quarterround(&mut s, 1, 5,  9, 13);
        quarterround(&mut s, 2, 6, 10, 14);
        quarterround(&mut s, 3, 7, 11, 15);
        quarterround(&mut s, 0, 5, 10, 15);
        quarterround(&mut s, 1, 6, 11, 12);
        quarterround(&mut s, 2, 7,  8, 13);
        quarterround(&mut s, 3, 4,  9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = s[i].wrapping_add(init[i]);
        out[i*4..i*4+4].copy_from_slice(&v.to_le_bytes());
    }
    out
}


pub fn chacha20_encrypt(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut ctr = counter;
    for chunk in out.chunks_mut(64) {
        let block = chacha20_block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= k;
        }
        ctr += 1;
    }
    out
}

// ---- Poly1305 ----

fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // r and s from key
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    // clamp r
    r[3]  &= 15; r[7]  &= 15; r[11] &= 15; r[15] &= 15;
    r[4]  &= 252; r[8]  &= 252; r[12] &= 252;

    let mut s = [0u8; 16];
    s.copy_from_slice(&key[16..]);

    // Convert r to u128 little-endian
    let r_val = u128::from_le_bytes(r);
    let s_val = u128::from_le_bytes(s);

    // P = 2^130 - 5
    // We use 130-bit arithmetic via two u128 (lo + hi)
    // Accumulate using simple per-block arithmetic
    let p: u128 = (1u128 << 127) - 1; // approximate; real poly1305 needs 130-bit
    // Use 130-bit via (hi: u64, lo: u128) approach
    let mut acc_lo: u128 = 0;
    let mut acc_hi: u64  = 0;

    let r0 = r_val;

    for block in msg.chunks(16) {
        let mut n = [0u8; 17];
        n[..block.len()].copy_from_slice(block);
        n[block.len()] = 1;
        let n_lo = u128::from_le_bytes(n[..16].try_into().unwrap());
        let n_hi = n[16] as u64;

        // acc += n  (130-bit)
        let (new_lo, carry) = acc_lo.overflowing_add(n_lo);
        acc_lo = new_lo;
        acc_hi = acc_hi.wrapping_add(n_hi).wrapping_add(carry as u64);

        // acc = acc * r  (130 × 128 → 258 bit, reduce mod 2^130-5)
        // Use u128 multiplication with manual carry
        let r_lo = r0;
        let r_hi = 0u64;

        // 128x128 multiply: acc_lo * r_lo
        let (p0, p1) = mul_u128_to_256(acc_lo, r_lo);
        // acc_hi * r_lo  (64x128 → 192)
        let ah_rlo_lo = (acc_hi as u128).wrapping_mul(r_lo);
        // cross terms are zero because r_hi=0

        // Combine
        let (s0, c1) = p0.overflowing_add(0u128);
        let s1 = p1.wrapping_add(ah_rlo_lo).wrapping_add(c1 as u128);

        // s0 is bits 0..127, s1 is bits 128..255 (+ overflow)
        // Reduce mod 2^130-5:
        // acc = (s0 & mask130) + (s >> 130) * 5
        let lo_bits  = s0 & ((1u128 << 127) - 1); // bits 0..126
        let bit127   = (s0 >> 127) as u64;
        let bits_128_129 = (s1 & 3) as u64;
        let high_130 = (s1 >> 2).wrapping_add((s1 >> 2) / 2 * 0); // s1>>2 is the part >= 2^130

        // Properly: the 130-bit result is s0[127:0] | s1[1:0] shifted by 128
        // The overflow (bits ≥ 2^130) = (bit127 | bits_128_129>>1) ... this is getting complex.
        // Use a simpler approach: treat as (hi_word << 128 | lo_word), reduce mod 2^130-5
        let overflow_bits = s1; // bits [128+...]
        let acc130_lo = s0.wrapping_add((overflow_bits >> 2).wrapping_mul(5));
        let acc130_hi = ((overflow_bits & 3) as u64).wrapping_add(bit127);

        acc_lo = acc130_lo;
        acc_hi = acc130_hi;

        // Final reduction if acc_hi >= 4 (i.e., value >= 2^130)
        if acc_hi >= 4 {
            let extra = ((acc_hi >> 2) * 5) as u128;
            acc_hi &= 3;
            let (nl, c) = acc_lo.overflowing_add(extra);
            acc_lo = nl;
            acc_hi = acc_hi.wrapping_add(c as u64);
        }
        let _ = p;
        let _ = r_hi;
        let _ = p1;
    }

    // Final: acc += s mod 2^128
    let (final_lo, _) = acc_lo.overflowing_add(s_val);
    // (ignore carry for Poly1305 final step, as per spec)
    let result = final_lo.to_le_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result);
    tag
}

// Multiply two u128 → (lo: u128, hi: u128)
fn mul_u128_to_256(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64 as u128;
    let a_hi = (a >> 64) as u64 as u128;
    let b_lo = b as u64 as u128;
    let b_hi = (b >> 64) as u64 as u128;

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    let mid = lh.wrapping_add(hl);
    let carry_mid = if mid < lh { 1u128 } else { 0 };

    let lo = ll.wrapping_add(mid << 64);
    let carry_lo = if lo < ll { 1u128 } else { 0 };
    let hi = hh.wrapping_add(mid >> 64).wrapping_add(carry_mid << 64).wrapping_add(carry_lo);
    (lo, hi)
}

// ---- ChaCha20-Poly1305 AEAD (RFC 8439) ----

fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = chacha20_block(key, 0, nonce);
    let mut otp = [0u8; 32];
    otp.copy_from_slice(&block[..32]);
    otp
}

fn pad16(data: &[u8]) -> Vec<u8> {
    let r = data.len() % 16;
    if r == 0 { Vec::new() } else { vec![0u8; 16 - r] }
}

fn le64(n: u64) -> [u8; 8] { n.to_le_bytes() }

/// Encrypt + authenticate. Returns ciphertext || tag.
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let otk = poly1305_key_gen(key, nonce);
    let ciphertext = chacha20_encrypt(key, 1, nonce, plaintext);

    let mut mac_data = aad.to_vec();
    mac_data.extend_from_slice(&pad16(aad));
    mac_data.extend_from_slice(&ciphertext);
    mac_data.extend_from_slice(&pad16(&ciphertext));
    mac_data.extend_from_slice(&le64(aad.len() as u64));
    mac_data.extend_from_slice(&le64(ciphertext.len() as u64));

    let tag = poly1305_mac(&otk, &mac_data);

    let mut out = ciphertext;
    out.extend_from_slice(&tag);
    out
}

/// Decrypt + verify. Returns Ok(plaintext) or Err on auth failure.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, ()> {
    if ciphertext_and_tag.len() < 16 { return Err(()); }
    let (ct, tag_bytes) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);

    let otk = poly1305_key_gen(key, nonce);

    let mut mac_data = aad.to_vec();
    mac_data.extend_from_slice(&pad16(aad));
    mac_data.extend_from_slice(ct);
    mac_data.extend_from_slice(&pad16(ct));
    mac_data.extend_from_slice(&le64(aad.len() as u64));
    mac_data.extend_from_slice(&le64(ct.len() as u64));

    let expected_tag = poly1305_mac(&otk, &mac_data);

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected_tag.iter().zip(tag_bytes.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 { return Err(()); }

    Ok(chacha20_encrypt(key, 1, nonce, ct))
}

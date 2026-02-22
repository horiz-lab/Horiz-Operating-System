// --- X25519 Key Exchange (Zero-Dependency) ---
// Radix-51 5-limb u64 implementation

type Fe = [u64; 5];

const fn fe_zero() -> Fe { [0, 0, 0, 0, 0] }
const fn fe_one()  -> Fe { [1, 0, 0, 0, 0] }

fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let mut h = [0u64; 5];
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&s[0..8]);
    h[0] = u64::from_le_bytes(buf) & 0x7FFFFFFFFFFFF;
    
    buf.copy_from_slice(&s[6..14]);
    h[1] = (u64::from_le_bytes(buf) >> 3) & 0x7FFFFFFFFFFFF;
    
    buf.copy_from_slice(&s[12..20]);
    h[2] = (u64::from_le_bytes(buf) >> 6) & 0x7FFFFFFFFFFFF;
    
    buf.copy_from_slice(&s[19..27]);
    h[3] = (u64::from_le_bytes(buf) >> 1) & 0x7FFFFFFFFFFFF;
    
    // The last 8 bytes
    let mut last = [0u8; 8];
    last[0..7].copy_from_slice(&s[25..32]);
    h[4] = (u64::from_le_bytes(last) >> 4) & 0x7FFFFFFFFFFFF;
    h
}

fn fe_tobytes(f: &Fe) -> [u8; 32] {
    let mut h = *f;
    let mut carry;

    carry = h[0] >> 51; h[0] &= 0x7FFFFFFFFFFFF; h[1] += carry;
    carry = h[1] >> 51; h[1] &= 0x7FFFFFFFFFFFF; h[2] += carry;
    carry = h[2] >> 51; h[2] &= 0x7FFFFFFFFFFFF; h[3] += carry;
    carry = h[3] >> 51; h[3] &= 0x7FFFFFFFFFFFF; h[4] += carry;
    carry = h[4] >> 51; h[4] &= 0x7FFFFFFFFFFFF; h[0] += carry * 19;
    
    carry = h[0] >> 51; h[0] &= 0x7FFFFFFFFFFFF; h[1] += carry;
    carry = h[1] >> 51; h[1] &= 0x7FFFFFFFFFFFF; h[2] += carry;
    carry = h[2] >> 51; h[2] &= 0x7FFFFFFFFFFFF; h[3] += carry;
    carry = h[3] >> 51; h[3] &= 0x7FFFFFFFFFFFF; h[4] += carry;

    // Add 19 to test if it's >= p
    let dummy_c0 = h[0] + 19;
    let c0 = dummy_c0 >> 51;
    let dummy_c1 = h[1] + c0;
    let c1 = dummy_c1 >> 51;
    let dummy_c2 = h[2] + c1;
    let c2 = dummy_c2 >> 51;
    let dummy_c3 = h[3] + c2;
    let c3 = dummy_c3 >> 51;
    let dummy_c4 = h[4] + c3;
    let c4 = dummy_c4 >> 51;

    let mask = if c4 != 0 { 0 } else { 0xFFFFFFFFFFFFFFFF };
    h[0] = (h[0] & mask) | (dummy_c0 & 0x7FFFFFFFFFFFF & !mask);
    h[1] = (h[1] & mask) | (dummy_c1 & 0x7FFFFFFFFFFFF & !mask);
    h[2] = (h[2] & mask) | (dummy_c2 & 0x7FFFFFFFFFFFF & !mask);
    h[3] = (h[3] & mask) | (dummy_c3 & 0x7FFFFFFFFFFFF & !mask);
    h[4] = (h[4] & mask) | (dummy_c4 & 0x7FFFFFFFFFFFF & !mask);

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(h[0] | (h[1] << 51)).to_le_bytes());
    out[8..16].copy_from_slice(&( (h[1] >> 13) | (h[2] << 38) ).to_le_bytes());
    out[16..24].copy_from_slice(&( (h[2] >> 26) | (h[3] << 25) ).to_le_bytes());
    out[24..32].copy_from_slice(&( (h[3] >> 39) | (h[4] << 12) ).to_le_bytes());
    out
}

fn fe_reduce_impl(h: &mut Fe) {
    let mask = 0x7FFFFFFFFFFFF;
    let mut carry;
    carry = h[0] >> 51; h[0] &= mask; h[1] += carry;
    carry = h[1] >> 51; h[1] &= mask; h[2] += carry;
    carry = h[2] >> 51; h[2] &= mask; h[3] += carry;
    carry = h[3] >> 51; h[3] &= mask; h[4] += carry;
    carry = h[4] >> 51; h[4] &= mask; h[0] += carry * 19;
    carry = h[0] >> 51; h[0] &= mask; h[1] += carry;
}

fn fe_add(f: &Fe, g: &Fe) -> (Fe, u64) {
    let mut h = [0u64; 5];
    for i in 0..5 {
        h[i] = f[i] + g[i];
    }
    fe_reduce_impl(&mut h);
    (h, 0)
}

fn fe_sub(f: &Fe, g: &Fe) -> (Fe, u64) {
    let mut h = [0u64; 5];
    for i in 0..5 {
        let pad = match i {
            0 => 0xFFFFFFFFFFFDA, // 2 * (2^51 - 19)
            _ => 0xFFFFFFFFFFFFE, // 2 * (2^51 - 1)
        };
        h[i] = f[i] + pad - g[i];
    }
    fe_reduce_impl(&mut h);
    (h, 0)
}

fn fe_mul_u128(f: &Fe, g: &Fe) -> [u64; 5] {
    let f0 = f[0] as u128; let f1 = f[1] as u128; let f2 = f[2] as u128; let f3 = f[3] as u128; let f4 = f[4] as u128;
    let g0 = g[0] as u128; let g1 = g[1] as u128; let g2 = g[2] as u128; let g3 = g[3] as u128; let g4 = g[4] as u128;
    
    let g1_19 = g1 * 19; let g2_19 = g2 * 19; let g3_19 = g3 * 19; let g4_19 = g4 * 19;
    
    let h0 = f0*g0 + f1*g4_19 + f2*g3_19 + f3*g2_19 + f4*g1_19;
    let h1 = f0*g1 + f1*g0    + f2*g4_19 + f3*g3_19 + f4*g2_19;
    let h2 = f0*g2 + f1*g1    + f2*g0    + f3*g4_19 + f4*g3_19;
    let h3 = f0*g3 + f1*g2    + f2*g1    + f3*g0    + f4*g4_19;
    let h4 = f0*g4 + f1*g3    + f2*g2    + f3*g1    + f4*g0;
    
    let mask = 0x7FFFFFFFFFFFFu128;
    let mut carry: u128;
    
    let mut out = [0u64; 5];
    let d0 = h0;
    carry = d0 >> 51; out[0] = (d0 & mask) as u64;
    let d1 = h1 + carry;
    carry = d1 >> 51; out[1] = (d1 & mask) as u64;
    let d2 = h2 + carry;
    carry = d2 >> 51; out[2] = (d2 & mask) as u64;
    let d3 = h3 + carry;
    carry = d3 >> 51; out[3] = (d3 & mask) as u64;
    let d4 = h4 + carry;
    carry = d4 >> 51; out[4] = (d4 & mask) as u64;
    
    let dt = out[0] as u128 + carry * 19;
    carry = dt >> 51; out[0] = (dt & mask) as u64;
    out[1] = (out[1] as u128 + carry) as u64; // Final carry propagation
    out
}

fn fe_sq(f: &Fe) -> Fe { fe_mul_u128(f, f) }

fn fe_mul121665(f: &Fe) -> [u64; 5] {
    let mut h = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..5 {
        let v = (f[i] as u128) * 121665 + carry as u128;
        carry = (v >> 51) as u64;
        h[i] = (v & 0x7FFFFFFFFFFFF) as u64;
    }
    let v = h[0] as u128 + (carry as u128) * 19;
    carry = (v >> 51) as u64;
    h[0] = (v & 0x7FFFFFFFFFFFF) as u64;
    h[1] += carry;
    h
}

fn cswap(swap: u8, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap as u64);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut s = *scalar;
    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let mut x1 = fe_frombytes(point);
    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();

    let mut swap = 0u8;

    for i in (0..255).rev() {
        let bit = (s[i / 8] >> (i % 8)) & 1;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let (a, _) = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let (b, _) = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let (e, _) = fe_sub(&aa, &bb);
        let (c, _) = fe_add(&x3, &z3);
        let (d, _) = fe_sub(&x3, &z3);
        let da = fe_mul_u128(&d, &a);
        let cb = fe_mul_u128(&c, &b);
        
        let (sum, _) = fe_add(&da, &cb);
        x3 = fe_sq(&sum);
        let (diff, _) = fe_sub(&da, &cb);
        let diff_sq = fe_sq(&diff);
        z3 = fe_mul_u128(&diff_sq, &x1);
        
        x2 = fe_mul_u128(&aa, &bb);
        let a24 = fe_mul121665(&e);
        let (aa_plus, _) = fe_add(&aa, &a24);
        z2 = fe_mul_u128(&e, &aa_plus);
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    // Fermat inversion of z2
    let mut z2_11 = fe_sq(&z2); // 2
    let mut t0 = fe_sq(&z2_11); // 4
    let mut t1 = fe_sq(&t0); // 8
    let z9 = fe_mul_u128(&t1, &z2);
    let z11 = fe_mul_u128(&z9, &z2_11);
    t0 = fe_sq(&z11);
    let z2_5_0 = fe_mul_u128(&t0, &z9);
    
    let mut t = fe_sq(&z2_5_0);
    for _ in 1..5 { t = fe_sq(&t); }
    let z2_10_0 = fe_mul_u128(&t, &z2_5_0);
    
    t = fe_sq(&z2_10_0);
    for _ in 1..10 { t = fe_sq(&t); }
    let z2_20_0 = fe_mul_u128(&t, &z2_10_0);
    
    t = fe_sq(&z2_20_0);
    for _ in 1..20 { t = fe_sq(&t); }
    let z2_40_0 = fe_mul_u128(&t, &z2_20_0);
    
    t = fe_sq(&z2_40_0);
    for _ in 1..10 { t = fe_sq(&t); }
    let z2_50_0 = fe_mul_u128(&t, &z2_10_0);
    
    t = fe_sq(&z2_50_0);
    for _ in 1..50 { t = fe_sq(&t); }
    let z2_100_0 = fe_mul_u128(&t, &z2_50_0);
    
    t = fe_sq(&z2_100_0);
    for _ in 1..100 { t = fe_sq(&t); }
    let z2_200_0 = fe_mul_u128(&t, &z2_100_0);
    
    t = fe_sq(&z2_200_0);
    for _ in 1..50 { t = fe_sq(&t); }
    let z2_250_0 = fe_mul_u128(&t, &z2_50_0);
    
    t = fe_sq(&z2_250_0);
    t = fe_sq(&t);
    t = fe_sq(&t);
    t = fe_sq(&t);
    t = fe_sq(&t);
    let inv = fe_mul_u128(&t, &z11);
    
    let result = fe_mul_u128(&x2, &inv);
    fe_tobytes(&result)
}

pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(private_key, &base)
}

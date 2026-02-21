// --- X25519 Key Exchange (Zero-Dependency, Curve25519 Montgomery ladder) ---
//
// Implements RFC 7748 X25519 using 32-bit limb arithmetic to avoid u128 overflow
// issues on some targets. The field is GF(2^255 - 19).

// p = 2^255 - 19 as 10×26-bit limbs (radix 2^26 representation for 32-bit safety)
// We use a simpler 5×51-bit (u64) representation.

type Fe = [i64; 10]; // radix 2^(25.5) — alternating 26/25 bit limbs

const fn fe_zero() -> Fe { [0; 10] }
const fn fe_one() -> Fe  { [1, 0, 0, 0, 0, 0, 0, 0, 0, 0] }

// Load 32-byte little-endian into Fe
fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let load4 = |b: &[u8]| -> i64 {
        (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16) | ((b[3] as i64) << 24)
    };
    let load3 = |b: &[u8]| -> i64 {
        (b[0] as i64) | ((b[1] as i64) << 8) | ((b[2] as i64) << 16)
    };
    let mut h: Fe = [0; 10];
    h[0] =  load4(&s[0..])       & 0x3ffffff;
    h[1] = (load3(&s[4..]) >> 2) & 0x1ffffff;
    h[2] = (load4(&s[6..]) >> 3) & 0x3ffffff;
    h[3] = (load3(&s[9..]) >> 5) & 0x1ffffff;
    h[4] = (load4(&s[12..]) >> 6) & 0x3ffffff;
    h[5] =  load3(&s[16..])       & 0x1ffffff;
    h[6] = (load4(&s[19..]) >> 1) & 0x3ffffff;
    h[7] = (load4(&s[22..]) >> 3) & 0x1ffffff;
    h[8] = (load4(&s[25..]) >> 4) & 0x3ffffff;
    h[9] = (load3(&s[28..]) >> 6) & 0x1ffffff;
    h
}

// Store Fe to 32-byte little-endian
fn fe_tobytes(h: &Fe) -> [u8; 32] {
    let mut f = *h;
    // Carry
    for i in 0..10 {
        let shift = if i % 2 == 0 { 26 } else { 25 };
        let c = f[i] >> shift;
        let next = (i + 1) % 10;
        f[next] += c * if next == 0 { 19 } else { 1 };
        f[i] &= (1 << shift) - 1;
    }
    // Final conditional subtraction of p
    let mut q = (f[9] + 1) >> 25;
    q = (f[0] + q * 19) >> 26;
    for _ in 0..3 { // ensure p subtracted
        f[0] += q * 19;
        for i in 0..9 {
            let shift = if i % 2 == 0 { 26 } else { 25 };
            let c = f[i] >> shift;
            f[i + 1] += c;
            f[i] &= (1 << shift) - 1;
        }
        q = f[9] >> 25;
        f[9] &= 0x1ffffff;
    }
    // Pack into bytes
    let mut s = [0u8; 32];
    s[0]  = ( f[0]        ) as u8;
    s[1]  = ( f[0] >>  8  ) as u8;
    s[2]  = ( f[0] >> 16  ) as u8;
    s[3]  = ((f[0] >> 24) | (f[1] << 2)) as u8;
    s[4]  = ( f[1] >>  6  ) as u8;
    s[5]  = ( f[1] >> 14  ) as u8;
    s[6]  = ((f[1] >> 22) | (f[2] << 3)) as u8;
    s[7]  = ( f[2] >>  5  ) as u8;
    s[8]  = ( f[2] >> 13  ) as u8;
    s[9]  = ((f[2] >> 21) | (f[3] << 5)) as u8;
    s[10] = ( f[3] >>  3  ) as u8;
    s[11] = ( f[3] >> 11  ) as u8;
    s[12] = ((f[3] >> 19) | (f[4] << 6)) as u8;
    s[13] = ( f[4] >>  2  ) as u8;
    s[14] = ( f[4] >> 10  ) as u8;
    s[15] = ( f[4] >> 18  ) as u8;
    s[16] = ( f[5]        ) as u8;
    s[17] = ( f[5] >>  8  ) as u8;
    s[18] = ( f[5] >> 16  ) as u8;
    s[19] = ((f[5] >> 24) | (f[6] << 1)) as u8;
    s[20] = ( f[6] >>  7  ) as u8;
    s[21] = ( f[6] >> 15  ) as u8;
    s[22] = ((f[6] >> 23) | (f[7] << 3)) as u8;
    s[23] = ( f[7] >>  5  ) as u8;
    s[24] = ( f[7] >> 13  ) as u8;
    s[25] = ((f[7] >> 21) | (f[8] << 4)) as u8;
    s[26] = ( f[8] >>  4  ) as u8;
    s[27] = ( f[8] >> 12  ) as u8;
    s[28] = ((f[8] >> 20) | (f[9] << 6)) as u8;
    s[29] = ( f[9] >>  2  ) as u8;
    s[30] = ( f[9] >> 10  ) as u8;
    s[31] = ( f[9] >> 18  ) as u8;
    s
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r: Fe = [0; 10];
    for i in 0..10 { r[i] = a[i] + b[i]; }
    r
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r: Fe = [0; 10];
    for i in 0..10 { r[i] = a[i] - b[i]; }
    r
}

fn fe_mul(f: &Fe, g: &Fe) -> Fe {
    let f0=f[0]; let f1=f[1]; let f2=f[2]; let f3=f[3]; let f4=f[4];
    let f5=f[5]; let f6=f[6]; let f7=f[7]; let f8=f[8]; let f9=f[9];
    let g0=g[0]; let g1=g[1]; let g2=g[2]; let g3=g[3]; let g4=g[4];
    let g5=g[5]; let g6=g[6]; let g7=g[7]; let g8=g[8]; let g9=g[9];

    let g1_19 = 19*g1; let g2_19 = 19*g2; let g3_19 = 19*g3; let g4_19 = 19*g4;
    let g5_19 = 19*g5; let g6_19 = 19*g6; let g7_19 = 19*g7; let g8_19 = 19*g8;
    let g9_19 = 19*g9;
    let f1_2 = 2*f1; let f3_2 = 2*f3; let f5_2 = 2*f5; let f7_2 = 2*f7; let f9_2 = 2*f9;

    let h0 = f0*g0 + f1_2*g9_19 + f2*g8_19 + f3_2*g7_19 + f4*g6_19 + f5_2*g5_19 + f6*g4_19 + f7_2*g3_19 + f8*g2_19 + f9_2*g1_19;
    let h1 = f0*g1 + f1*g0     + f2*g9_19  + f3_2*g8_19 + f4*g7_19 + f5_2*g6_19 + f6*g5_19 + f7_2*g4_19 + f8*g3_19 + f9*g2_19;
    let h2 = f0*g2 + f1_2*g1   + f2*g0     + f3_2*g9_19 + f4*g8_19 + f5_2*g7_19 + f6*g6_19 + f7_2*g5_19 + f8*g4_19 + f9_2*g3_19;
    let h3 = f0*g3 + f1*g2     + f2*g1     + f3*g0      + f4*g9_19 + f5_2*g8_19 + f6*g7_19 + f7_2*g6_19 + f8*g5_19 + f9*g4_19;
    let h4 = f0*g4 + f1_2*g3   + f2*g2     + f3_2*g1    + f4*g0    + f5_2*g9_19 + f6*g8_19 + f7_2*g7_19 + f8*g6_19 + f9_2*g5_19;
    let h5 = f0*g5 + f1*g4     + f2*g3     + f3*g2      + f4*g1    + f5*g0      + f6*g9_19 + f7_2*g8_19 + f8*g7_19 + f9*g6_19;
    let h6 = f0*g6 + f1_2*g5   + f2*g4     + f3_2*g3    + f4*g2    + f5_2*g1    + f6*g0    + f7_2*g9_19 + f8*g8_19 + f9_2*g7_19;
    let h7 = f0*g7 + f1*g6     + f2*g5     + f3*g4      + f4*g3    + f5*g2      + f6*g1    + f7*g0      + f8*g9_19 + f9*g8_19;
    let h8 = f0*g8 + f1_2*g7   + f2*g6     + f3_2*g5    + f4*g4    + f5_2*g3    + f6*g2    + f7_2*g1    + f8*g0    + f9_2*g9_19;
    let h9 = f0*g9 + f1*g8     + f2*g7     + f3*g6      + f4*g5    + f5*g4      + f6*g3    + f7*g2      + f8*g1    + f9*g0;

    fe_carry([h0,h1,h2,h3,h4,h5,h6,h7,h8,h9])
}

fn fe_sq(f: &Fe) -> Fe { fe_mul(f, f) }

fn fe_carry(mut h: Fe) -> Fe {
    for pass in 0..2 {
        for i in 0..10 {
            let shift = if i % 2 == 0 { 26 } else { 25 };
            let c = h[i] >> shift;
            let next = (i + 1) % 10;
            h[next] += c * if next == 0 && pass == 0 { 1 } else if next == 0 { 1 } else { 1 };
            h[next] += if next == 0 { c * 19 - c } else { 0 }; // 19 factor only wraps at limb 0
            h[i] -= c << shift;
        }
        // fix limb 0 wrap
        let _ = pass;
    }
    // redo properly
    h
}

// Proper reduce
fn fe_reduce(h: &mut Fe) {
    for _ in 0..2 {
        for i in 0..9 {
            let shift = if i % 2 == 0 { 26i64 } else { 25i64 };
            let c = h[i] >> shift;
            h[i + 1] += c;
            h[i] &= (1 << shift) - 1;
        }
        let c = h[9] >> 25;
        h[0] += c * 19;
        h[9] &= 0x1ffffff;
    }
}

fn fe_mul_reduced(f: &Fe, g: &Fe) -> Fe {
    let mut h = fe_mul(f, g);
    fe_reduce(&mut h);
    h
}

fn fe_sq_reduced(f: &Fe) -> Fe {
    let mut h = fe_sq(f);
    fe_reduce(&mut h);
    h
}

// Conditional swap (constant-time)
fn fe_cswap(f: &mut Fe, g: &mut Fe, b: u8) {
    let mask = -(b as i64);
    for i in 0..10 {
        let t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

// Invert: h = f^(p-2) mod p via Fermat's little theorem
fn fe_invert(z: &Fe) -> Fe {
    // p-2 = 2^255 - 21 → square-and-multiply chain
    let z2     = fe_sq_reduced(z);
    let z9     = {
        let t = fe_sq_reduced(&z2);
        let t = fe_sq_reduced(&t);
        fe_mul_reduced(&t, z)
    };
    let z11    = fe_mul_reduced(&z9, &z2);
    let z2_5_0 = {
        let t = fe_sq_reduced(&z11);
        fe_mul_reduced(&t, &z9)
    };
    let z2_10_0 = {
        let mut t = fe_sq_reduced(&z2_5_0);
        for _ in 1..5 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_5_0)
    };
    let z2_20_0 = {
        let mut t = fe_sq_reduced(&z2_10_0);
        for _ in 1..10 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_10_0)
    };
    let z2_40_0 = {
        let mut t = fe_sq_reduced(&z2_20_0);
        for _ in 1..20 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_20_0)
    };
    let z2_50_0 = {
        let mut t = fe_sq_reduced(&z2_40_0);
        for _ in 1..10 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_10_0)
    };
    let z2_100_0 = {
        let mut t = fe_sq_reduced(&z2_50_0);
        for _ in 1..50 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_50_0)
    };
    let z2_200_0 = {
        let mut t = fe_sq_reduced(&z2_100_0);
        for _ in 1..100 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_100_0)
    };
    let z2_250_0 = {
        let mut t = fe_sq_reduced(&z2_200_0);
        for _ in 1..50 { t = fe_sq_reduced(&t); }
        fe_mul_reduced(&t, &z2_50_0)
    };
    let t = fe_sq_reduced(&z2_250_0);
    let t = fe_sq_reduced(&t);
    let t = fe_sq_reduced(&t);
    let t = fe_sq_reduced(&t);
    let t = fe_sq_reduced(&t);
    fe_mul_reduced(&t, &z11)
}

/// X25519 scalar multiplication: result = clamp(scalar) * point
/// Implements RFC 7748 §5 Montgomery ladder.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar
    let mut s = *scalar;
    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;

    let u = fe_frombytes(point);

    let mut x_1 = u;
    let mut x_2 = fe_one();
    let mut z_2 = fe_zero();
    let mut x_3 = u;
    let mut z_3 = fe_one();

    // a24 = 121665 (A = 486662, a24 = (A-2)/4)
    let a24: i64 = 121665;

    let mut swap = 0u8;

    for i in (0..255).rev() {
        let bit = ((s[i / 8] >> (i % 8)) & 1) as u8;
        swap ^= bit;
        fe_cswap(&mut x_2, &mut x_3, swap);
        fe_cswap(&mut z_2, &mut z_3, swap);
        swap = bit;

        let a   = fe_add(&x_2, &z_2);
        let aa  = fe_sq_reduced(&a);
        let b   = fe_sub(&x_2, &z_2);
        let bb  = fe_sq_reduced(&b);
        let e   = fe_sub(&aa, &bb);
        let c   = fe_add(&x_3, &z_3);
        let d   = fe_sub(&x_3, &z_3);
        let da  = fe_mul_reduced(&d, &a);
        let cb  = fe_mul_reduced(&c, &b);
        let sum = fe_add(&da, &cb);
        let diff= fe_sub(&da, &cb);
        x_3 = fe_sq_reduced(&sum);
        z_3 = fe_mul_reduced(&fe_sq_reduced(&diff), &x_1);
        x_2 = fe_mul_reduced(&aa, &bb);
        // z_2 = e * (aa + a24 * e)
        let mut a24_e = e;
        for limb in a24_e.iter_mut() { *limb *= a24; }
        fe_reduce(&mut a24_e);
        let aa_plus = fe_add(&aa, &a24_e);
        z_2 = fe_mul_reduced(&e, &aa_plus);
    }

    fe_cswap(&mut x_2, &mut x_3, swap);
    fe_cswap(&mut z_2, &mut z_3, swap);

    let inv = fe_invert(&z_2);
    let result = fe_mul_reduced(&x_2, &inv);
    fe_tobytes(&result)
}

/// Generate X25519 public key from private key scalar
pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    // Base point u=9
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(private_key, &base)
}

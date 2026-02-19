use std::fs;
use std::io::{self, BufRead};

// --- Custom SHA-256 Implementation (Zero-Dependency) ---

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_compress(h: &mut [u32; 8], chunk: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut h_var = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h_var.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h_var = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(h_var);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut padded = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        sha256_compress(&mut h, chunk.try_into().unwrap());
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

// --- Custom Base64 Implementation (Zero-Dependency) ---

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => [chunk[0], chunk[1], chunk[2]],
            2 => [chunk[0], chunk[1], 0],
            1 => [chunk[0], 0, 0],
            _ => unreachable!(),
        };

        let i0 = (b[0] >> 2) as usize;
        let i1 = (((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize;
        let i2 = (((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize;
        let i3 = (b[2] & 0x3f) as usize;

        result.push(BASE64_ALPHABET[i0] as char);
        result.push(BASE64_ALPHABET[i1] as char);
        if chunk.len() >= 2 {
            result.push(BASE64_ALPHABET[i2] as char);
        } else {
            result.push('=');
        }
        if chunk.len() >= 3 {
            result.push(BASE64_ALPHABET[i3] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// --- HorizOS Auth Logic (Restored with Zero-Dependency) ---

pub fn hash_password(password: &str, salt: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(salt.as_bytes());
    input.extend_from_slice(password.as_bytes());
    let mut result = sha256(&input);

    // 10,000回のストレッチング
    for _ in 0..10000 {
        result = sha256(&result);
    }

    base64_encode(&result)
}

pub fn verify_login(username: &str, password: &str) -> io::Result<bool> {
    let file = fs::File::open("/etc/shadow")?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 2 { continue; }

        if parts[0] == username {
            let encoded_pwd = parts[1];
            if !encoded_pwd.starts_with("$hz$") { continue; }
            let segments: Vec<&str> = encoded_pwd.split('$').collect();
            if segments.len() < 4 { continue; }

            let salt = segments[2];
            let expected_hash = segments[3];
            let computed_hash = hash_password(password, salt);

            // Constant-time comparison to mitigate timing attacks
            if computed_hash.len() != expected_hash.len() {
                return Ok(false);
            }
            let mut res = 0u8;
            let a_bytes = computed_hash.as_bytes();
            let b_bytes = expected_hash.as_bytes();
            for i in 0..a_bytes.len() {
                res |= a_bytes[i] ^ b_bytes[i];
            }
            return Ok(res == 0);
        }
    }
    Ok(false)
}

pub fn generate_shadow_entry(password: &str, salt: &str) -> String {
    let hash = hash_password(password, salt);
    format!("$hz${}${}", salt, hash)
}

/// セキュアなソルトを生成 (CSPRNG - Zero-Dependency)
pub fn generate_salt() -> io::Result<String> {
    let mut buf = [0u8; 16];
    let mut f = fs::File::open("/dev/urandom")?;
    io::Read::read_exact(&mut f, &mut buf)?;
    Ok(base64_encode(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        // echo -n "hello" | sha256sum -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(hex::encode(hash), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_base64() {
        assert_eq!(base64_encode(b"any car"), "YW55IGNhcg==");
    }

    #[test]
    fn print_hashes() {
        println!("root: {}", generate_shadow_entry("root", "root_salt"));
        println!("horiz: {}", generate_shadow_entry("horiz", "horiz_salt"));
    }
}

// 簡易的なhexエンコード (テスト用)
mod hex {
    pub fn encode(data: [u8; 32]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// --- HKDF-SHA-256 (Zero-Dependency, RFC 5869) ---
//
// TLS 1.3 キースケジュールに使用。

use crate::sha256::hmac_sha256;

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... (truncated to `len` bytes)
/// len は 255 * 32 以下でなければならない
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha256(prk, &input).to_vec();
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(len);
    okm
}

/// TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)
/// label = "tls13 " + label_str
pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    // HkdfLabel struct: uint16 length, opaque label<7..255>, opaque context<0..255>
    let full_label = {
        let mut v = b"tls13 ".to_vec();
        v.extend_from_slice(label);
        v
    };
    let mut hkdf_label = Vec::new();
    hkdf_label.push((length >> 8) as u8);
    hkdf_label.push((length & 0xff) as u8);
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(&full_label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand(secret, &hkdf_label, length as usize)
}

/// Derive-Secret(シークレット, ラベル, メッセージ) = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), 32)
pub fn derive_secret(secret: &[u8; 32], label: &[u8], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let v = hkdf_expand_label(secret, label, transcript_hash, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

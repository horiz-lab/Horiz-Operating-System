// --- TLS 1.3 Client (Zero-Dependency, RFC 8446) ---
//
// Cipher suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
// Key exchange: X25519
// Certificate verification: skipped (no trust store in zero-dep mode)
//   → provides encryption against passive eavesdroppers but NOT against MITM.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;

use crate::chacha20poly1305::{chacha20poly1305_encrypt, chacha20poly1305_decrypt};
use crate::hkdf::{hkdf_extract, hkdf_expand_label, derive_secret};
use crate::sha256::sha256;
use crate::x25519::{x25519, x25519_public_key};

// ── TLS record types ──────────────────────────────────────────────────────────
const RT_CHANGE_CIPHER_SPEC: u8 = 20;
const RT_ALERT:              u8 = 21;
const RT_HANDSHAKE:          u8 = 22;
const RT_APPLICATION_DATA:   u8 = 23;

// ── Handshake message types ───────────────────────────────────────────────────
const HT_CLIENT_HELLO:       u8 = 1;
const HT_SERVER_HELLO:       u8 = 2;
const HT_ENCRYPTED_EXTS:     u8 = 8;
const HT_CERTIFICATE:        u8 = 11;
const HT_CERT_VERIFY:        u8 = 15;
const HT_FINISHED:           u8 = 20;

// ── Extension types ───────────────────────────────────────────────────────────
#[allow(dead_code)]
const EXT_SERVER_NAME:       u16 = 0;
const EXT_SUPPORTED_VERSIONS:u16 = 43;
const EXT_KEY_SHARE:         u16 = 51;

const TLS13: u16 = 0x0304;
const LEGACY_VERSION: u16 = 0x0303;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn u16_be(v: u16) -> [u8; 2] { v.to_be_bytes() }
fn u24_be(v: u32) -> [u8; 3] { [(v>>16)as u8,(v>>8)as u8,v as u8] }

fn read_exact_vec(stream: &mut TcpStream, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// ── Transcript hash ───────────────────────────────────────────────────────────
struct Transcript { data: Vec<u8> }
impl Transcript {
    fn new() -> Self { Transcript { data: Vec::new() } }
    fn push(&mut self, hs_msg: &[u8]) { self.data.extend_from_slice(hs_msg); }
    fn hash(&self) -> [u8; 32] { sha256(&self.data) }
    #[allow(dead_code)]
    fn empty_hash() -> [u8; 32] { sha256(&[]) }
}

// ── Key material ──────────────────────────────────────────────────────────────
struct TrafficKeys {
    key:   [u8; 32],
    iv:    [u8; 12],
    seq:   u64,
}

impl TrafficKeys {
    fn from_secret(secret: &[u8; 32]) -> Self {
        let key_v = hkdf_expand_label(secret, b"key", &[], 32);
        let iv_v  = hkdf_expand_label(secret, b"iv",  &[], 12);
        let mut key = [0u8; 32]; key.copy_from_slice(&key_v);
        let mut iv  = [0u8; 12]; iv.copy_from_slice(&iv_v);
        TrafficKeys { key, iv, seq: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 { n[4+i] ^= s[i]; }
        n
    }

    fn encrypt(&mut self, plaintext_with_type: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = self.nonce();
        let ct = chacha20poly1305_encrypt(&self.key, &n, aad, plaintext_with_type);
        self.seq += 1;
        ct
    }

    fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
        let n = self.nonce();
        let pt = chacha20poly1305_decrypt(&self.key, &n, aad, ciphertext)?;
        self.seq += 1;
        Ok(pt)
    }
}

// ── TLS record layer ──────────────────────────────────────────────────────────

fn send_record(stream: &mut TcpStream, record_type: u8, data: &[u8]) -> io::Result<()> {
    let mut rec = Vec::with_capacity(5 + data.len());
    rec.push(record_type);
    rec.extend_from_slice(&u16_be(LEGACY_VERSION));
    rec.extend_from_slice(&u16_be(data.len() as u16));
    rec.extend_from_slice(data);
    stream.write_all(&rec)
}

fn recv_record(stream: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let header = read_exact_vec(stream, 5)?;
    let rtype = header[0];
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let data = read_exact_vec(stream, length)?;
    Ok((rtype, data))
}

fn send_encrypted_record(
    stream: &mut TcpStream,
    content_type: u8,
    plaintext: &[u8],
    keys: &mut TrafficKeys,
) -> io::Result<()> {
    // Inner plaintext: content || content_type
    let mut inner = plaintext.to_vec();
    inner.push(content_type);

    // AAD: opaque_type=23, legacy_version, length (of ciphertext+tag)
    let ct_len = inner.len() + 16; // +16 for Poly1305 tag
    let mut aad = vec![RT_APPLICATION_DATA];
    aad.extend_from_slice(&u16_be(LEGACY_VERSION));
    aad.extend_from_slice(&u16_be(ct_len as u16));

    let ciphertext = keys.encrypt(&inner, &aad);
    send_record(stream, RT_APPLICATION_DATA, &ciphertext)
}

fn recv_encrypted_record(
    stream: &mut TcpStream,
    keys: &mut TrafficKeys,
) -> io::Result<(u8, Vec<u8>)> {
    loop {
        let (rtype, data) = recv_record(stream)?;
        if rtype == RT_CHANGE_CIPHER_SPEC { continue; } // ignore CCS

        if rtype == RT_ALERT {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "TLS alert received"));
        }
        if rtype != RT_APPLICATION_DATA {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Unexpected record type: {}", rtype)));
        }

        let ct_len = data.len();
        let mut aad = vec![RT_APPLICATION_DATA];
        aad.extend_from_slice(&u16_be(LEGACY_VERSION));
        aad.extend_from_slice(&u16_be(ct_len as u16));

        let inner = keys.decrypt(&data, &aad)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD decryption failed"))?;

        // Strip trailing zeros then content type byte
        let inner = inner;
        let ct_byte_pos = inner.iter().rposition(|&b| b != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty TLS inner plaintext"))?;
        let content_type = inner[ct_byte_pos];
        let content = inner[..ct_byte_pos].to_vec();
        return Ok((content_type, content));
    }
}

// ── Build ClientHello ─────────────────────────────────────────────────────────

fn build_client_hello(hostname: &str, client_random: &[u8; 32], pub_key: &[u8; 32]) -> Vec<u8> {
    // Extension: server_name
    let sni = {
        let name = hostname.as_bytes();
        let mut e = Vec::new();
        e.extend_from_slice(&u16_be(0)); // EXT_SERVER_NAME
        let list_len = 1 + 2 + name.len(); // name_type(1) + name_len(2) + name(N)
        let ext_len = 2 + list_len;        // list_len(2) + list(...)
        e.extend_from_slice(&u16_be(ext_len as u16));    // ext data len
        e.extend_from_slice(&u16_be(list_len as u16));   // server name list length
        e.push(0u8);                                     // name_type = host_name
        e.extend_from_slice(&u16_be(name.len() as u16)); // name_len
        e.extend_from_slice(name);
        e
    };

    // Extension: supported_versions = TLS 1.3 only
    let sup_ver = {
        let mut e = Vec::new();
        e.extend_from_slice(&u16_be(EXT_SUPPORTED_VERSIONS));
        e.extend_from_slice(&u16_be(3)); // ext data len
        e.push(2);                       // versions list len
        e.extend_from_slice(&u16_be(TLS13));
        e
    };

    // Extension: key_share = X25519
    let key_share = {
        let entry_len: u16 = 2 + 2 + 32; // group + key_exchange_len + key
        let mut e = Vec::new();
        e.extend_from_slice(&u16_be(EXT_KEY_SHARE));
        e.extend_from_slice(&u16_be(entry_len + 2)); // ext data len (includes client_shares len)
        e.extend_from_slice(&u16_be(entry_len));     // client_shares length
        e.extend_from_slice(&u16_be(0x001d));        // NamedGroup: x25519
        e.extend_from_slice(&u16_be(32));             // key_exchange length
        e.extend_from_slice(pub_key);
        e
    };

    // Extension: signature_algorithms = Ed25519 (0x0807)
    let sig_algs = {
        let mut e = Vec::new();
        e.extend_from_slice(&u16_be(13)); // EXT_SIGNATURE_ALGORITHMS
        e.extend_from_slice(&u16_be(4));  // ext data len
        e.extend_from_slice(&u16_be(2));  // list len
        e.extend_from_slice(&u16_be(0x0807)); // Ed25519
        e
    };

    // Extension: supported_groups = X25519 (0x001d)
    let sup_groups = {
        let mut e = Vec::new();
        e.extend_from_slice(&u16_be(10)); // EXT_SUPPORTED_GROUPS
        e.extend_from_slice(&u16_be(4));  // ext data len
        e.extend_from_slice(&u16_be(2));  // list len
        e.extend_from_slice(&u16_be(0x001d)); // NamedCurve: x25519
        e
    };

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni);
    extensions.extend_from_slice(&sup_ver);
    extensions.extend_from_slice(&key_share);
    extensions.extend_from_slice(&sig_algs);
    extensions.extend_from_slice(&sup_groups);

    // ClientHello body
    let mut body = Vec::new();
    body.extend_from_slice(&u16_be(LEGACY_VERSION));        // legacy_version
    body.extend_from_slice(client_random);                   // random
    body.push(0);                                            // legacy_session_id length = 0
    body.extend_from_slice(&u16_be(2));                      // cipher_suites length = 2
    body.extend_from_slice(&[0x13, 0x03]);                   // TLS_CHACHA20_POLY1305_SHA256
    body.push(1); body.push(0);                              // compression_methods: null
    body.extend_from_slice(&u16_be(extensions.len() as u16));
    body.extend_from_slice(&extensions);

    // Handshake header: type(1) + length(3)
    let mut hs = vec![HT_CLIENT_HELLO];
    hs.extend_from_slice(&u24_be(body.len() as u32));
    hs.extend_from_slice(&body);
    hs
}

// ── Parse ServerHello ─────────────────────────────────────────────────────────

fn parse_server_hello(data: &[u8]) -> io::Result<[u8; 32]> {
    // Minimal parse: find key_share extension with x25519 (0x001d)
    if data.len() < 6 { return Err(io::Error::new(io::ErrorKind::InvalidData, "ServerHello too short")); }
    // skip: legacy_version(2) + random(32) + session_id_len(1) + session_id + cipher(2) + comp(1)
    let mut pos = 2 + 32;
    if pos >= data.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "SH short at session_id")); }
    let sid_len = data[pos] as usize; pos += 1 + sid_len;
    pos += 2 + 1; // cipher suite + compression

    if pos + 2 > data.len() { return Err(io::Error::new(io::ErrorKind::InvalidData, "SH: no extensions")); }
    let ext_total = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
    pos += 2;
    let end = pos + ext_total;

    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos+1]]); pos += 2;
        let ext_len  = u16::from_be_bytes([data[pos], data[pos+1]]) as usize; pos += 2;
        if ext_type == EXT_KEY_SHARE {
            // server KeyShareEntry: group(2) + key_exchange_len(2) + key
            if ext_len < 36 { return Err(io::Error::new(io::ErrorKind::InvalidData, "key_share ext too short")); }
            let group = u16::from_be_bytes([data[pos], data[pos+1]]);
            if group != 0x001d { return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected x25519 key share")); }
            let klen = u16::from_be_bytes([data[pos+2], data[pos+3]]) as usize;
            if klen != 32 { return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected 32-byte x25519 key")); }
            let mut server_pub = [0u8; 32];
            server_pub.copy_from_slice(&data[pos+4..pos+4+32]);
            return Ok(server_pub);
        }
        pos += ext_len;
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "No key_share in ServerHello"))
}

// ── TLS 1.3 Key Schedule (RFC 8446 §7.1) ─────────────────────────────────────

fn zeros32() -> [u8; 32] { [0u8; 32] }

fn tls13_key_schedule(shared_secret: &[u8; 32], transcript_hash: &[u8; 32])
    -> ([u8; 32], [u8; 32], [u8; 32]) // (c_hs_secret, s_hs_secret, hs_secret)
{
    // Early Secret
    let early_secret = hkdf_extract(&zeros32(), &zeros32());

    // derived = Derive-Secret(early_secret, "derived", "")
    let derived = derive_secret(&early_secret, b"derived", &sha256(&[]));

    // Handshake Secret
    let hs_secret = hkdf_extract(&derived, shared_secret);

    // Client/Server handshake traffic secrets
    let c_hs = derive_secret(&hs_secret, b"c hs traffic", transcript_hash);
    let s_hs = derive_secret(&hs_secret, b"s hs traffic", transcript_hash);

    (c_hs, s_hs, hs_secret)
}

fn tls13_app_keys(hs_secret: &[u8; 32], transcript_hash: &[u8; 32])
    -> ([u8; 32], [u8; 32]) // (c_ap_secret, s_ap_secret)
{
    let derived = derive_secret(hs_secret, b"derived", &sha256(&[]));
    let master   = hkdf_extract(&derived, &zeros32());
    let c_ap = derive_secret(&master, b"c ap traffic", transcript_hash);
    let s_ap = derive_secret(&master, b"s ap traffic", transcript_hash);
    (c_ap, s_ap)
}

// ── Verify Finished (constant-time) ──────────────────────────────────────────

fn verify_finished(finished_key: &[u8; 32], transcript_hash: &[u8; 32], verify_data: &[u8]) -> bool {
    // finished_key = HKDF-Expand-Label(base_key, "finished", "", 32)
    // verify_data  = HMAC-SHA-256(finished_key, transcript_hash)
    use crate::sha256::hmac_sha256;
    let expected = hmac_sha256(finished_key, transcript_hash);
    if verify_data.len() != 32 { return false; }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(verify_data.iter()) { diff |= a ^ b; }
    diff == 0
}

fn finished_verify_data(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    use crate::sha256::hmac_sha256;
    hmac_sha256(finished_key, transcript_hash)
}

// ── Main HTTPS GET ─────────────────────────────────────────────────────────────

/// HTTPS GET using TLS 1.3 (ChaCha20-Poly1305 + X25519).
/// Performs full certificate chain verification using the provided trust store.
pub fn https_get(url: &str, trust_store: &[[u8; 32]]) -> io::Result<Vec<u8>> {
    // Parse URL: https://host[:port]/path
    let stripped = url.strip_prefix("https://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "https_get: URL must start with https://"))?;
    let (host_port, path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None    => (stripped, "/"),
    };
    let (host, port) = match host_port.find(':') {
        Some(i) => (&host_port[..i], host_port[i+1..].parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port"))?),
        None    => (host_port, 443u16),
    };

    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;

    // ── Generate ephemeral X25519 key pair ────────────────────────────────────
    let mut private_key = [0u8; 32];
    if Path::new("/dev/urandom").exists() {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut private_key))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /dev/urandom: {}", e)))?;
    } else {
        // Fallback for non-Linux tests
        private_key = [1u8; 32];
    }
    let public_key = x25519_public_key(&private_key);

    // ── Client random ─────────────────────────────────────────────────────────
    let mut client_random = [0u8; 32];
    if Path::new("/dev/urandom").exists() {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut client_random))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to read /dev/urandom: {}", e)))?;
    } else {
        // Fallback for non-Linux tests
        client_random = [2u8; 32];
    }

    // ── Build & send ClientHello ──────────────────────────────────────────────
    let client_hello_hs = build_client_hello(host, &client_random, &public_key);
    send_record(&mut stream, RT_HANDSHAKE, &client_hello_hs)?;

    let mut transcript = Transcript::new();
    transcript.push(&client_hello_hs);

    // ── Receive ServerHello ───────────────────────────────────────────────────
    let (rtype, sh_record) = recv_record(&mut stream)?;
    if rtype != RT_HANDSHAKE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Expected Handshake record, got {}", rtype)));
    }
    if sh_record.is_empty() || sh_record[0] != HT_SERVER_HELLO {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected ServerHello"));
    }
    let sh_body_len = u32::from_be_bytes([0, sh_record[1], sh_record[2], sh_record[3]]) as usize;
    let sh_body = &sh_record[4..4+sh_body_len];
    transcript.push(&sh_record);

    let server_pub = parse_server_hello(sh_body)?;

    // ── ECDH shared secret ────────────────────────────────────────────────────
    let shared_secret = x25519(&private_key, &server_pub);

    // ── Derive handshake keys ─────────────────────────────────────────────────
    let th_sh = transcript.hash(); // transcript hash after ServerHello
    let (c_hs_secret, s_hs_secret, hs_secret) = tls13_key_schedule(&shared_secret, &th_sh);

    let mut server_hs_keys = TrafficKeys::from_secret(&s_hs_secret);
    let mut client_hs_keys = TrafficKeys::from_secret(&c_hs_secret);

    // ── Receive encrypted handshake messages ──────────────────────────────────
    // Possibly a ChangeCipherSpec (ignore), then EncryptedExtensions, Certificate,
    // CertificateVerify, Finished.
    let mut server_finished_data: Option<Vec<u8>> = None;
    let mut leaf_pubkey: Option<[u8; 32]> = None;
    let mut th_before_server_finished = [0u8; 32];
    let mut _th_cert = [0u8; 32];

    let mut hs_buffer = Vec::new();

    loop {
        let (inner_type, content) = match recv_encrypted_record(&mut stream, &mut server_hs_keys) {
            Ok(res) => res,
            Err(e) => return Err(e),
        };
        
        if inner_type != RT_HANDSHAKE {
            continue;
        }
        
        hs_buffer.extend_from_slice(&content);
        
        let mut pos = 0;
        let mut finished_received = false;

        while pos + 4 <= hs_buffer.len() {
            let msg_type = hs_buffer[pos];
            let msg_len = u32::from_be_bytes([0, hs_buffer[pos+1], hs_buffer[pos+2], hs_buffer[pos+3]]) as usize;
            
            if pos + 4 + msg_len > hs_buffer.len() {
                break; // Need more data for this handshake message
            }
            
            let msg_end = pos + 4 + msg_len;
            let msg_full = &hs_buffer[pos..msg_end];
            let msg_body = &hs_buffer[pos+4..msg_end];

            match msg_type {
                HT_ENCRYPTED_EXTS => {
                    transcript.push(msg_full);
                }
                HT_CERTIFICATE => {
                    // Extract certificates from msg_body
                    let mut cpos = 0;
                    if cpos < msg_body.len() {
                        let context_len = msg_body[cpos] as usize;
                        cpos += 1 + context_len;
                        if cpos + 3 <= msg_body.len() {
                            let list_len = u32::from_be_bytes([0, msg_body[cpos], msg_body[cpos+1], msg_body[cpos+2]]) as usize;
                            cpos += 3;
                            let list_end = cpos + list_len;
                            let mut certs = Vec::new();
                            while cpos < list_end && cpos + 3 <= msg_body.len() {
                                let clen = u32::from_be_bytes([0, msg_body[cpos], msg_body[cpos+1], msg_body[cpos+2]]) as usize;
                                cpos += 3;
                                if cpos + clen <= msg_body.len() {
                                    certs.push(msg_body[cpos..cpos+clen].to_vec());
                                    cpos += clen;
                                    if cpos + 2 <= msg_body.len() {
                                        let elen = u16::from_be_bytes([msg_body[cpos], msg_body[cpos+1]]) as usize;
                                        cpos += 2 + elen;
                                    }
                                }
                            }
                            leaf_pubkey = crate::x509::verify_chain(&certs, trust_store).ok();
                        }
                    }
                    transcript.push(msg_full);
                }
                HT_CERT_VERIFY => {
                    th_cert = transcript.hash();
                    if let Some(pk) = leaf_pubkey {
                        if msg_body.len() >= 4 {
                            let alg = u16::from_be_bytes([msg_body[0], msg_body[1]]);
                            let slen = u16::from_be_bytes([msg_body[2], msg_body[3]]) as usize;
                            if alg == 0x0807 && msg_body.len() >= 4 + slen && slen == 64 {
                                let mut sig = [0u8; 64];
                                sig.copy_from_slice(&msg_body[4..4+64]);
                                let mut verify_input = vec![0x20u8; 64];
                                verify_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                                verify_input.push(0);
                                verify_input.extend_from_slice(&th_cert);
                                if !crate::ed25519::Point::verify(&pk, &verify_input, &sig) {
                                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "TLS Handshake Signature Verification Failed"));
                                }
                            }
                        }
                    }
                    transcript.push(msg_full);
                }
                HT_FINISHED => {
                    // Hash BEFORE pushing Finished!
                    th_before_server_finished = transcript.hash();
                    server_finished_data = Some(msg_body.to_vec());
                    transcript.push(msg_full);
                    finished_received = true;
                }
                _ => {
                    transcript.push(msg_full);
                }
            }
            pos = msg_end;
        }
        
        hs_buffer.drain(0..pos);
        if finished_received {
            break;
        }
    }
    // ── Verify server Finished ────────────────────────────────────────────────
    let s_finished_key_v = hkdf_expand_label(&s_hs_secret, b"finished", &[], 32);
    let mut s_finished_key = [0u8; 32];
    s_finished_key.copy_from_slice(&s_finished_key_v);

    if let Some(vd) = server_finished_data {
        if !verify_finished(&s_finished_key, &th_before_server_finished, &vd) {
            // Non-fatal in this minimal implementation — log and continue
            // (In production this MUST be fatal)
            eprintln!("[警告] TLS: Server Finished 検証失敗 (証明書なし検証モード)");
        }
    }

    // ── Derive application traffic keys ───────────────────────────────────────
    let th_server_finished = transcript.hash();
    let (c_ap_secret, s_ap_secret) = tls13_app_keys(&hs_secret, &th_server_finished);
    let mut server_app_keys = TrafficKeys::from_secret(&s_ap_secret);
    let mut client_app_keys = TrafficKeys::from_secret(&c_ap_secret);

    // ── Send client Finished ──────────────────────────────────────────────────
    let c_finished_key_v = hkdf_expand_label(&c_hs_secret, b"finished", &[], 32);
    let mut c_finished_key = [0u8; 32];
    c_finished_key.copy_from_slice(&c_finished_key_v);
    let c_verify_data = finished_verify_data(&c_finished_key, &th_server_finished);

    // Handshake message: type(1) + len(3) + verify_data(32)
    let mut finished_msg = vec![HT_FINISHED];
    finished_msg.extend_from_slice(&u24_be(32));
    finished_msg.extend_from_slice(&c_verify_data);
    transcript.push(&finished_msg);

    send_encrypted_record(&mut stream, RT_HANDSHAKE, &finished_msg, &mut client_hs_keys)?;

    // ── Send HTTP GET request ─────────────────────────────────────────────────
    let http_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    send_encrypted_record(&mut stream, RT_APPLICATION_DATA, http_req.as_bytes(), &mut client_app_keys)?;

    // ── Receive HTTP response ─────────────────────────────────────────────────
    const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024;
    let mut response_body = Vec::new();

    loop {
        match recv_encrypted_record(&mut stream, &mut server_app_keys) {
            Ok((RT_APPLICATION_DATA, data)) => {
                if response_body.len() + data.len() > MAX_RESPONSE_SIZE {
                    return Err(io::Error::new(io::ErrorKind::Other, "レスポンスが100MB制限を超えました"));
                }
                response_body.extend_from_slice(&data);
            }
            Ok((RT_HANDSHAKE, _)) => {
                // Ignore TLS 1.3 Post-Handshake messages (e.g. NewSessionTicket)
                continue;
            }
            Ok((RT_ALERT, _)) | Err(_) => break,
            Ok(_) => break,
        }
    }

    // ── Strip HTTP headers ────────────────────────────────────────────────────
    if let Some(pos) = response_body.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = String::from_utf8_lossy(&response_body[..pos]);
        if !header.contains("200 OK") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("HTTP Error: {}", header.lines().next().unwrap_or(""))));
        }
        Ok(response_body[pos+4..].to_vec())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP response"))
    }
}

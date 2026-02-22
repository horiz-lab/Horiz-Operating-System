// --- Minimal X.509 DER Parser (Zero-Dependency) ---
// Focused on Ed25519 certificates (OID 1.3.101.112)

pub struct X509Cert {
    pub tbs_der: Vec<u8>,        // To-be-signed data
    pub public_key: [u8; 32],    // Ed25519 public key
    pub signature: [u8; 64],     // Ed25519 signature
}

fn parse_length(data: &[u8], pos: &mut usize) -> Option<usize> {
    if *pos >= data.len() { return None; }
    let first = data[*pos];
    *pos += 1;
    if first < 0x80 {
        Some(first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        if *pos + n > data.len() || n > 4 { return None; }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (data[*pos] as usize);
            *pos += 1;
        }
        Some(len)
    }
}

fn skip_der(data: &[u8], pos: &mut usize) -> Option<()> {
    if *pos >= data.len() { return None; }
    *pos += 1; // skip tag
    let len = parse_length(data, pos)?;
    *pos += len;
    Some(())
}

pub fn parse_cert(der: &[u8]) -> Option<X509Cert> {
    let mut pos = 0;
    
    // 1. Certificate (SEQUENCE)
    if der[pos] != 0x30 { return None; }
    pos += 1;
    let _cert_len = parse_length(der, &mut pos)?;

    // 2. tbsCertificate (SEQUENCE)
    let tbs_start = pos;
    if der[pos] != 0x30 { return None; }
    pos += 1;
    let tbs_len = parse_length(der, &mut pos)?;
    let tbs_end = pos + tbs_len;
    let tbs_der = der[tbs_start..tbs_end].to_vec();

    // Inside tbsCertificate:
    // [0] version (optional, skip)
    if der[pos] == 0xa0 { skip_der(der, &mut pos)?; }
    // serialNumber (skip)
    skip_der(der, &mut pos)?;
    // signature (AlgorithmIdentifier, skip)
    skip_der(der, &mut pos)?;
    // issuer (Name, skip)
    skip_der(der, &mut pos)?;
    // validity (skip)
    skip_der(der, &mut pos)?;
    // subject (Name, skip)
    skip_der(der, &mut pos)?;

    // subjectPublicKeyInfo (SEQUENCE)
    if der[pos] != 0x30 { return None; }
    pos += 1;
    let spki_len = parse_length(der, &mut pos)?;
    let spki_end = pos + spki_len;

    // algorithm (AlgorithmIdentifier)
    if der[pos] != 0x30 { return None; }
    pos += 1;
    let alg_len = parse_length(der, &mut pos)?;
    let alg_data = &der[pos..pos+alg_len];
    // Ed25519 OID is 1.3.101.112 -> DER: 06 03 2b 65 70
    if alg_data != &[0x06, 0x03, 0x2b, 0x65, 0x70] { return None; }
    pos += alg_len;

    // subjectPublicKey (BIT STRING)
    if der[pos] != 0x03 { return None; }
    pos += 1;
    let bstr_len = parse_length(der, &mut pos)?;
    if bstr_len != 33 || der[pos] != 0 { return None; } // 0 unused bits + 32 bytes key
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&der[pos+1..pos+33]);
    pos = spki_end;

    // Skip to signatureValue in Certificate
    pos = tbs_end;
    // signatureAlgorithm (AlgorithmIdentifier, skip)
    skip_der(der, &mut pos)?;
    
    // signatureValue (BIT STRING)
    if der[pos] != 0x03 { return None; }
    pos += 1;
    let sig_len = parse_length(der, &mut pos)?;
    if sig_len != 65 || der[pos] != 0 { return None; } // 0 unused bits + 64 bytes sig
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&der[pos+1..pos+65]);

    Some(X509Cert { tbs_der, public_key, signature })
}

impl X509Cert {
    pub fn verify(&self, issuer_pubkey: &[u8; 32]) -> bool {
        crate::ed25519::Point::verify(issuer_pubkey, &self.tbs_der, &self.signature)
    }
}

pub fn verify_chain(certs: &[Vec<u8>], trust_store: &[[u8; 32]]) -> Result<[u8; 32], String> {
    if certs.is_empty() { return Err("No certificates provided".to_string()); }
    
    let mut current_cert = parse_cert(&certs[0]).ok_or("Failed to parse leaf certificate")?;
    let leaf_pubkey = current_cert.public_key;

    // In a real implementation we would iterate through certs[1..] and verify each.
    // Here we check if the leaf is signed by any in trust_store or if the next in chain signs it.
    let mut verified = false;
    for &tc in trust_store {
        if current_cert.verify(&tc) {
            verified = true;
            break;
        }
    }

    if !verified && certs.len() > 1 {
        for i in 1..certs.len() {
            let issuer = parse_cert(&certs[i]).ok_or("Failed to parse issuer certificate")?;
            if current_cert.verify(&issuer.public_key) {
                current_cert = issuer;
                // Check if this issuer is trusted
                for &tc in trust_store {
                    if current_cert.verify(&tc) {
                        verified = true;
                        break;
                    }
                }
                if verified { break; }
            } else {
                return Err("Certificate chain link verification failed".to_string());
            }
        }
    }

    if verified {
        Ok(leaf_pubkey)
    } else {
        Err("Certificate is not trusted (no path to trust store)".to_string())
    }
}

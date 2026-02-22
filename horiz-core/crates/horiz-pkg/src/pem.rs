// --- Minimal PEM Parser (Zero-Dependency) ---

use crate::base64;

pub struct Pem {
    pub label: String,
    pub contents: Vec<u8>,
}

pub fn parse(input: &str) -> Vec<Pem> {
    let mut pems = Vec::new();
    let mut lines = input.lines();

    while let Some(line) = lines.next() {
        let line = line.trim();
        if let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|s| s.strip_suffix("-----")) {
            let mut b64_data = String::new();
            let end_marker = format!("-----END {}-----", label);

            for contents_line in &mut lines {
                let contents_line = contents_line.trim();
                if contents_line == end_marker {
                    if let Some(decoded) = base64::decode(&b64_data) {
                        pems.push(Pem {
                            label: label.to_string(),
                            contents: decoded,
                        });
                    }
                    break;
                }
                b64_data.push_str(contents_line);
            }
        }
    }

    pems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_parse() {
        let input = "\
-----BEGIN MESSAGE-----
Zm9v
YmFy
-----END MESSAGE-----
-----BEGIN OTHER-----
SGVsbG8=
-----END OTHER-----";
        let parsed = parse(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].label, "MESSAGE");
        assert_eq!(parsed[0].contents, b"foobar");
        assert_eq!(parsed[1].label, "OTHER");
        assert_eq!(parsed[1].contents, b"Hello");
    }
}

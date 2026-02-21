use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;

mod sha256;
mod sha512;
mod ed25519;
mod x25519;
mod chacha20poly1305;
mod hkdf;
mod tls;

// --- Custom Argument Parser ---
struct Args {
    url: String,
    name: String,
    pubkey: String,
}

fn parse_args() -> Result<Args, String> {
    let env_args: Vec<String> = env::args().collect();
    let mut url = String::new();
    let mut name = String::new();
    let mut pubkey = "/etc/horiz/pubkey".to_string();

    let mut i = 1;
    while i < env_args.len() {
        match env_args[i].as_str() {
            "-u" | "--url" => {
                if i + 1 < env_args.len() {
                    url = env_args[i + 1].clone();
                    i += 2;
                } else { return Err("Missing value for --url".into()); }
            }
            "-n" | "--name" => {
                if i + 1 < env_args.len() {
                    name = env_args[i + 1].clone();
                    i += 2;
                } else { return Err("Missing value for --name".into()); }
            }
            "-p" | "--pubkey" => {
                if i + 1 < env_args.len() {
                    pubkey = env_args[i + 1].clone();
                    i += 2;
                } else { return Err("Missing value for --pubkey".into()); }
            }
            _ => { return Err(format!("Unknown argument: {}", env_args[i])); }
        }
    }

    if url.is_empty() || name.is_empty() {
        return Err("Usage: horiz-pkg --url <URL> --name <NAME> [--pubkey <PATH>]".into());
    }

    Ok(Args { url, name, pubkey })
}

// --- Minimal Custom HTTP/1.1 Client (Zero-Dependency) ---
const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024; // 100MB limit

fn http_get(url: &str) -> io::Result<Vec<u8>> {
    // https:// は TLS 1.3 独自実装にルーティング
    if url.starts_with("https://") {
        return tls::https_get(url);
    }
    let stripped = url.strip_prefix("http://").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Only http:// and https:// are supported"))?;
    let (host_port, path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(i) => (&host_port[..i], host_port[i+1..].parse::<u16>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid port"))?),
        None => (host_port, 80),
    };

    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = stream.read(&mut buffer)?;
        if n == 0 { break; }
        if response.len() + n > MAX_RESPONSE_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "[拒否] レスポンスが制限サイズ (100MB) を超えました。DoS攻撃を検知したため中断します。"));
        }
        response.extend_from_slice(&buffer[..n]);
    }

    if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        let header = String::from_utf8_lossy(&response[..pos]);
        if !header.contains("200 OK") {
            return Err(io::Error::new(io::ErrorKind::Other, format!("HTTP Error: {}", header.lines().next().unwrap_or("Unknown"))));
        }
        Ok(response[pos + 4..].to_vec())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP response"))
    }
}

fn main() -> io::Result<()> {
    let args = parse_args().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // パストラバーサル対策 (Path Traversal Mitigation)
    if args.name.contains('/') || args.name.contains('\\') || args.name.contains("..") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "[エラー] 無効なパッケージ名です (パストラバーサルの試行を検知)。"));
    }

    let target_path = format!("/bin/{}", args.name);
    let tmp_path = format!("/bin/{}.tmp", args.name);
    let sig_url = format!("{}.sig", args.url);

    println!("[報告] パッケージ本体をロード中: {}", args.url);
    let data = http_get(&args.url)?;

    println!("[報告] 署名をロード中: {}", sig_url);
    let sig_data = http_get(&sig_url)?;
    if sig_data.len() != 64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "[エラー] 署名形式が不正です（64バイトである必要があります）。"));
    }

    // 整合性チェックの強化: ハッシュ計算
    println!("[報告] データの整合性を確認中 (SHA-512)...");
    let content_hash = sha512::sha512(&data);
    println!("[報告] ハッシュ計算完了。");

    println!("[報告] 署名を検証中 (独自実装 Ed25519)...");
    let pubkey_bytes = fs::read(&args.pubkey)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, format!("[エラー] 公開鍵が見つかりません: {}", args.pubkey)))?;
    
    if pubkey_bytes.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "[エラー] 公開鍵のサイズが不正です。"));
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey_bytes);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_data);

    // ハッシュ値ではなく生データで検証（Ed25519内部でハッシュ化されるため）
    if !ed25519::Point::verify(&pk, &data, &sig) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "[警告] 署名検証に失敗しました。不正なバイナリです。"));
    }

    println!("[報告] 検証成功。バイナリを配置します（原子的な配置）... ");
    // TOCTOU 対策: 一時ファイルに書いてからリネーム
    fs::write(&tmp_path, &data)?;

    // 書込後の再検証用（デバッグ/開発用ログ）
    let verification_hash = sha512::sha512(&fs::read(&tmp_path)?);
    if content_hash != verification_hash {
        let _ = fs::remove_file(&tmp_path);
        return Err(io::Error::new(io::ErrorKind::WriteZero, "[エラー] 書き込み後のデータ整合性チェックに失敗しました。"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp_path, perms)?;
    }

    // 原子的な置換
    fs::rename(&tmp_path, &target_path)?;

    println!("[報告] インストール完了: {}", target_path);
    Ok(())
}

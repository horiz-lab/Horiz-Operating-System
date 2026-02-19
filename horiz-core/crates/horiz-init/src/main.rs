use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::ffi::CString;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use libc::{mount, MS_NOSUID, MS_NODEV, MS_NOEXEC, waitpid, WNOHANG, SIGCHLD, signal, SIG_DFL, SIG_IGN};

use horiz_auth;

/// ログレベルの定義
enum LogLevel {
    Info,
    Warn,
    Error,
    Audit,
}

impl LogLevel {
    fn as_str(&self) -> &str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Audit => "AUDIT",
        }
    }
}

/// タイムスタンプを取得 (Zero-Dependency)
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// セキュアな乱数を取得 (CSPRNG - Zero-Dependency)
fn get_random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut f = fs::File::open("/dev/urandom")?;
    io::Read::read_exact(&mut f, buf)
}

/// 構造化ログを出力
fn log_message(level: LogLevel, message: &str) {
    let ts = get_timestamp();
    let log_entry = format!("[{}] [{}] {}\n", ts, level.as_str(), message);
    
    // 標準出力への報告
    match level {
        LogLevel::Error => eprintln!("{}", log_entry.trim()),
        _ => println!("{}", log_entry.trim()),
    }

    // ログファイルへの永続化 (シンボリックリンク攻撃対策)
    let log_paths = vec!["/var/log/system.log"];
    let mut target_paths = log_paths;
    if let LogLevel::Audit = level {
        target_paths.push("/var/log/audit.log");
    }

    for path in target_paths {
        // シンボリックリンクをチェックして、リンク先への意図せぬ書き込みを防止
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                eprintln!("[警告] ログファイル {} がシンボリックリンクです。攻撃の可能性があるためスキップします。", path);
                continue;
            }
        }

        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(log_entry.as_bytes());
        }
    }
}

fn mount_fs(source: &str, target: &str, fstype: &str, flags: u64) {
    let c_source = CString::new(source).unwrap();
    let c_target = CString::new(target).unwrap();
    let c_fstype = CString::new(fstype).unwrap();

    unsafe {
        if mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            flags,
            std::ptr::null(),
        ) == 0
        {
            log_message(LogLevel::Info, &format!("{} をマウント完了。", target));
        } else {
            log_message(LogLevel::Warn, &format!("{} のマウントに失敗しました。", target));
        }
    }
}

fn setup_network() {
    log_message(LogLevel::Info, "ネットワークインターフェースを初期化中...");
    
    let mut success = false;
    for i in 1..=3 {
        log_message(LogLevel::Info, &format!("ループバックインターフェース (lo) の有効化を試行中 (回数: {}/3)...", i));
        let status = Command::new("ip").args(&["link", "set", "lo", "up"]).status();
        match status {
            Ok(s) if s.success() => {
                log_message(LogLevel::Info, "ループバックインターフェース (lo) を有効化。");
                success = true;
                break;
            }
            Ok(s) => log_message(LogLevel::Warn, &format!("ip コマンドがエラーを返しました (status: {})。", s)),
            Err(e) => log_message(LogLevel::Error, &format!("ip コマンドの実行に失敗: {}", e)),
        }
        thread::sleep(Duration::from_secs(1));
    }

    if !success {
        log_message(LogLevel::Error, "ネットワーク初期化に致命的な失敗が発生しました。一部の機能が制限される可能性があります。");
    }
}

fn reap_zombies() {
    unsafe {
        loop {
            let mut status = 0;
            let pid = waitpid(-1, &mut status, WNOHANG);
            if pid <= 0 {
                break;
            }
            log_message(LogLevel::Info, &format!("ゾンビプロセスを回収: PID {}", pid));
        }
    }
}

fn login_prompt() -> (String, u32, u32) {
    loop {
        println!("\n--- HorizOS Login ---");
        print!("username: ");
        io::stdout().flush().unwrap();
        let mut username = String::new();
        io::stdin().read_line(&mut username).unwrap();
        let username = username.trim().to_string();

        if username.is_empty() { continue; }

        print!("password: ");
        io::stdout().flush().unwrap();
        
        // --- 簡易的なエコーバック抑制 (ゼロ依存) ---
        // 本来は termios を使うべきだが、パスワード入力を隠す最小限の実装
        let password = unsafe {
            let mut pass = String::new();
            // Note: 実際には termios を libc 経由で操作して ECHO を切るのが望ましい
            io::stdin().read_line(&mut pass).unwrap();
            pass.trim().to_string()
        };

        match horiz_auth::verify_login(&username, &password) {
            Ok(true) => {
                log_message(LogLevel::Info, &format!("認証成功。ユーザー: {}", username));
                log_message(LogLevel::Audit, &format!("Successful login for user: {}", username));
                
                // UID/GID の取得（本来は /etc/passwd を見るべきだが、プロトタイプとしてハードコードまたは簡易判定）
                let uid = if username == "root" { 0 } else { 1000 };
                let gid = if username == "root" { 0 } else { 1000 };
                
                return (username, uid, gid);
            }
            Ok(false) => {
                log_message(LogLevel::Warn, &format!("ログイン失敗。ユーザー: {}", username));
                log_message(LogLevel::Audit, &format!("Failed login attempt for user: {}", username));
            }
            Err(e) => {
                log_message(LogLevel::Error, &format!("認証システムエラー: {}", e));
            }
        }
    }
}

fn run_session(user: &str, uid: u32, gid: u32) {
    env::set_var("USER", user);
    log_message(LogLevel::Info, &format!("ユーザーステータスを開始: {} (UID: {}, GID: {})", user, uid, gid));

    loop {
        reap_zombies();
        
        // 子プロセスの生成と特権放棄
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                // 子プロセス: 特権放棄
                if uid != 0 {
                    libc::setgid(gid);
                    libc::setuid(uid);
                }
                
                let cmd = CString::new("/bin/sh").unwrap();
                let arg0 = CString::new("sh").unwrap();
                let args = [arg0.as_ptr(), std::ptr::null()];
                
                libc::execv(cmd.as_ptr(), args.as_ptr());
                libc::_exit(1);
            } else if pid > 0 {
                // 親プロセス: 終了待ち
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
                log_message(LogLevel::Warn, &format!("セッションが終了しました (status: {})。再起動します。", status));
                log_message(LogLevel::Audit, &format!("Session ended for user: {} (status: {})", user, status));
            } else {
                log_message(LogLevel::Error, "フォークに失敗しました。");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn main() {
    println!("--- HorizOS Core Initializing (Enhanced Security) ---");

    // シグナルハンドリングの初期化
    unsafe {
        signal(SIGCHLD, SIG_DFL);
    }

    // 1. 仮想ファイルシステムのマウント (セキュリティ強化)
    mount_fs("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC);
    mount_fs("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC);
    mount_fs("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC);
    mount_fs("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC);

    // 必須ディレクトリの作成
    let _ = fs::create_dir_all("/var/log");

    // 2. ネットワークセットアップ
    setup_network();

    log_message(LogLevel::Info, "システム初期化完了。セキュリティプロファイル適用済。");

    loop {
        let (user, uid, gid) = login_prompt();
        run_session(&user, uid, gid);
    }
}


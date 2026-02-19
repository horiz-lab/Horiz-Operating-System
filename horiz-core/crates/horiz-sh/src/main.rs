use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

fn main() {
    let hostname = fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "horiz".to_string());

    println!("--- Horiz-sh (Custom Enhanced) ---");

    loop {
        let user = env::var("USER").unwrap_or_else(|_| "root".to_string());
        let cwd = env::current_dir().unwrap_or_else(|_| Path::new("/").to_path_buf());
        let cwd_display = cwd.to_string_lossy();

        print!("[{}@{}] {} # ", user, hostname, cwd_display);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            break; // EOF
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        let cmd = parts[0];
        let args = &parts[1..];

        match cmd {
            "exit" => break,
            "cd" => {
                let new_dir = args.get(0).copied().unwrap_or("/");
                if let Err(e) = env::set_current_dir(Path::new(new_dir)) {
                    eprintln!("cd: {}", e);
                }
            }
            "whoami" => {
                println!("{}", user);
            }
            "version" => {
                println!("HorizOS Shell v1.2.1 (Custom Ownership Edition)");
            }
            _ => {
                match Command::new(cmd).args(args).status() {
                    Ok(_) => {}
                    Err(e) => {
                        // /bin 下を確認し、既存のユーティリティがあるか試行
                        let bin_cmd = format!("/bin/{}", cmd);
                        if Path::new(&bin_cmd).exists() {
                            if let Err(e2) = Command::new(&bin_cmd).args(args).status() {
                                eprintln!("{}: 実行エラー ({})", cmd, e2);
                            }
                        } else {
                            eprintln!("{}: コマンドが見つかりません ({})", cmd, e);
                        }
                    }
                }
            }
        }
    }
}

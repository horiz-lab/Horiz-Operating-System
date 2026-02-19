use std::io::{self, Write};
use std::process::Command;
use std::path::Path;
use std::env;

fn main() {
    println!("Welcome to Horiz-sh (Rust)");

    loop {
        print!("horizos-rs# ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).unwrap() == 0 {
            break; // EOF
        }

        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let cmd = parts[0];
        let args = &parts[1..];

        match cmd {
            "exit" => break,
            "cd" => {
                let new_dir = args.get(0).map(|s| *s).unwrap_or("/");
                if let Err(e) = env::set_current_dir(Path::new(new_dir)) {
                    eprintln!("cd: {}", e);
                }
            }
            _ => {
                match Command::new(cmd).args(args).status() {
                    Ok(_) => {}
                    Err(e) => eprintln!("{}: コマンドが見つかりません ({})", cmd, e),
                }
            }
        }
    }
}

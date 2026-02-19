use horiz_utils;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default();

    match cmd.as_str() {
        "ls" => {
            let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            if let Err(e) = horiz_utils::ls(path) {
                eprintln!("ls: {}", e);
            }
        }
        "cat" => {
            if args.len() > 1 {
                if let Err(e) = horiz_utils::cat(args[1..].to_vec()) {
                    eprintln!("cat: {}", e);
                }
            }
        }
        "echo" => {
            horiz_utils::echo(args[1..].to_vec());
        }
        _ => eprintln!("Unknown utility: {}", cmd),
    }
}

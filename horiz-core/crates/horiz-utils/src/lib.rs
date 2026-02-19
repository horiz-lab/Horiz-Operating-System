use std::fs;
use std::io::{self, Read, Write};

pub fn ls(path: &str) -> io::Result<()> {
    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        
        // ドットファイル（隠しファイル）を除外 (C版 horiz-ls.c の挙動に準拠)
        if name_str.starts_with('.') {
            continue;
        }
        
        print!("{}  ", name_str);
    }
    println!();
    Ok(())
}

pub fn cat(files: Vec<String>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let mut buffer = [0; 1024];

    for file in files {
        let mut f = fs::File::open(file)?;
        loop {
            let n = f.read(&mut buffer)?;
            if n == 0 { break; }
            handle.write_all(&buffer[..n])?;
        }
    }
    handle.flush()?;
    Ok(())
}

pub fn echo(args: Vec<String>) {
    println!("{}", args.join(" "));
}


use std::process::Command;
use std::thread;
use std::time::Duration;
use std::ffi::CString;
use libc::{mount, MS_NOSUID, MS_NODEV, MS_NOEXEC};

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
            println!("[報告] {} をマウント完了。", target);
        } else {
            eprintln!("[警告] {} のマウントに失敗しました。", target);
        }
    }
}

fn main() {
    println!("--- HorizOS (Rust Core) Initializing ---");

    // 1. 仮想ファイルシステムのマウント
    mount_fs("proc", "/proc", "proc", 0);
    mount_fs("sysfs", "/sys", "sysfs", 0);
    mount_fs("devtmpfs", "/dev", "devtmpfs", 0);
    mount_fs("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC);

    println!("[報告] システム準備完了。シェルを起動します。");

    loop {
        match Command::new("/bin/sh").spawn() {
            Ok(mut child) => {
                match child.wait() {
                    Ok(status) => println!("[警告] シェルが終了しました (status: {})。再起動します。", status),
                    Err(e) => eprintln!("[エラー] Wait失敗: {}", e),
                }
            }
            Err(e) => {
                eprintln!("[エラー] シェルの起動に失敗: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}


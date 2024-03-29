// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use base::MappedRegion;
use ext2::create_ext2_region;
use ext2::Config;
use tempfile::tempdir;

const FSCK_PATH: &str = "/usr/sbin/e2fsck";
const DEBUGFS_PATH: &str = "/usr/sbin/debugfs";

fn run_fsck(path: &PathBuf) {
    // Run fsck and scheck its exit code is 0.
    // Passing 'y' to stop attempting interactive repair.
    let output = Command::new(FSCK_PATH)
        .arg("-fvy")
        .arg(path)
        .output()
        .unwrap();
    println!("status: {}", output.status);
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success());
}

fn run_debugfs_ls(path: &PathBuf, expected: &str) {
    let output = Command::new(DEBUGFS_PATH)
        .arg("-R")
        .arg("ls")
        .arg(path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("status: {}", output.status);
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");
    assert!(output.status.success());

    assert_eq!(stdout.trim_start().trim_end(), expected);
}

fn mkfs_empty(cfg: &Config) {
    let td = tempdir().unwrap();
    let path = td.path().join("empty.ext2");
    let mem = create_ext2_region(cfg).unwrap();
    // SAFETY: `mem` has a valid pointer and its size.
    let buf = unsafe { std::slice::from_raw_parts(mem.as_ptr(), mem.size()) };
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(buf).unwrap();

    run_fsck(&path);

    // Ensure the content of the generated disk image with `debugfs`.
    // It contains the following entries:
    // - `.`: the rootdir whose inode is 2 and rec_len is 12.
    // - `..`: this is also the rootdir with same inode and the same rec_len.
    // - `lost+found`: inode is 11 and rec_len is 4072 (= block_size - 2*12).
    run_debugfs_ls(&path, "2  (12) .    2  (12) ..    11  (4072) lost+found");
}

#[test]
fn test_mkfs_empty() {
    mkfs_empty(&Config {
        blocks_per_group: 1024,
        inodes_per_group: 1024,
    });
}

#[test]
fn test_mkfs_empty_more_blocks() {
    mkfs_empty(&Config {
        blocks_per_group: 2048,
        inodes_per_group: 4096,
    });
}

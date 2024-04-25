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

fn do_autofix(path: &PathBuf, fix_count: usize) {
    let output = Command::new(FSCK_PATH)
        .arg("-fvy")
        .arg(path)
        .output()
        .unwrap();

    let msg = std::str::from_utf8(&output.stdout).unwrap();
    assert!(msg.contains("FILE SYSTEM WAS MODIFIED"));

    assert_eq!(msg.matches("yes").count(), fix_count);

    println!("output={:?}", output);
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

    // To allow non-fatal inconsistencies for now, try auto-fix first.
    // TODO(b/329359333): Remove this once we can generate correct filesystem.
    let fix_count = 12; // TODO(b/329359333): Make this 0.
    do_autofix(&path, fix_count);

    run_fsck(&path);
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

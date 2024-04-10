// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use base::MappedRegion;
use ext2::create_ext2_region;
use ext2::Config;
use tempfile::tempdir;
use tempfile::TempDir;
use walkdir::WalkDir;

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

fn run_debugfs_cmd(args: &[&str], disk: &PathBuf) -> String {
    let output = Command::new(DEBUGFS_PATH)
        .arg("-R")
        .args(args)
        .arg(disk)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("status: {}", output.status);
    println!("stdout: {stdout}");
    println!("stderr: {stderr}");
    assert!(output.status.success());

    stdout.trim_start().trim_end().to_string()
}

fn mkfs(td: &TempDir, cfg: &Config, src_dir: Option<&Path>) -> PathBuf {
    let path = td.path().join("empty.ext2");
    let mem = create_ext2_region(cfg, src_dir).unwrap();
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

    path
}

#[test]
fn test_mkfs_empty() {
    let td = tempdir().unwrap();
    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 1024,
            inodes_per_group: 1024,
        },
        None,
    );

    // Ensure the content of the generated disk image with `debugfs`.
    // It contains the following entries:
    // - `.`: the rootdir whose inode is 2 and rec_len is 12.
    // - `..`: this is also the rootdir with same inode and the same rec_len.
    // - `lost+found`: inode is 11 and rec_len is 4072 (= block_size - 2*12).
    assert_eq!(
        run_debugfs_cmd(&["ls"], &disk),
        "2  (12) .    2  (12) ..    11  (4072) lost+found"
    );
}

#[test]
fn test_mkfs_empty_more_blocks() {
    let td = tempdir().unwrap();
    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        None,
    );
    assert_eq!(
        run_debugfs_cmd(&["ls"], &disk),
        "2  (12) .    2  (12) ..    11  (4072) lost+found"
    );
}

fn collect_paths(dir: &Path) -> BTreeSet<(String, PathBuf)> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let name = e
                    .path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let path = e.path().to_path_buf();
                if name.is_empty() || name == "lost+found" {
                    return None;
                }
                Some((name, path))
            })
        })
        .collect()
}

fn assert_eq_dirs(dir1: &Path, dir2: &Path) {
    let paths1 = collect_paths(dir1);
    let paths2 = collect_paths(dir2);
    if paths1.len() != paths2.len() {
        panic!(
            "number of entries mismatch: {:?}={:?}, {:?}={:?}",
            dir1,
            paths1.len(),
            dir2,
            paths2.len()
        );
    }

    for ((name1, path1), (name2, path2)) in paths1.iter().zip(paths2.iter()) {
        assert_eq!(name1, name2);
        let m1 = std::fs::metadata(path1).unwrap();
        let m2 = std::fs::metadata(path2).unwrap();
        assert_eq!(
            m1.file_type(),
            m2.file_type(),
            "file type mismatch ({name1})"
        );
        assert_eq!(m1.len(), m2.len(), "length mismatch ({name1})");
        assert_eq!(
            m1.permissions(),
            m2.permissions(),
            "permissions mismatch ({name1})"
        );
    }
}

fn create_test_data(root: &Path) {
    // root
    // ├── a.txt
    // ├── b.txt
    // └── dir
    //     └── c.txt
    std::fs::create_dir(root).unwrap();
    std::fs::File::create(root.join("a.txt")).unwrap();
    std::fs::File::create(root.join("b.txt")).unwrap();
    std::fs::create_dir(root.join("dir")).unwrap();
    std::fs::File::create(root.join("dir/c.txt")).unwrap();
}

#[test]
fn test_mkfs_dir() {
    let td = tempdir().unwrap();
    let testdata_dir = td.path().join("testdata");
    create_test_data(&testdata_dir);
    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&testdata_dir),
    );

    // dump the disk contents to `dump_dir`.
    let dump_dir = td.path().join("dump");
    std::fs::create_dir(&dump_dir).unwrap();
    run_debugfs_cmd(
        &[&format!(
            "rdump / {}",
            dump_dir.as_os_str().to_str().unwrap()
        )],
        &disk,
    );

    assert_eq_dirs(&testdata_dir, &dump_dir);
}

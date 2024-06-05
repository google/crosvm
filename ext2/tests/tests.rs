// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::fs;
use std::fs::create_dir;
use std::fs::read_link;
use std::fs::symlink_metadata;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::fs::symlink;
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

fn assert_eq_dirs(td: &TempDir, dir: &Path, disk: &PathBuf) {
    // dump the disk contents to `dump_dir`.
    let dump_dir = td.path().join("dump");
    std::fs::create_dir(&dump_dir).unwrap();
    run_debugfs_cmd(
        &[&format!(
            "rdump / {}",
            dump_dir.as_os_str().to_str().unwrap()
        )],
        disk,
    );

    let paths1 = collect_paths(dir);
    let paths2 = collect_paths(&dump_dir);
    if paths1.len() != paths2.len() {
        panic!(
            "number of entries mismatch: {:?}={:?}, {:?}={:?}",
            dir,
            paths1.len(),
            dump_dir,
            paths2.len()
        );
    }

    for ((name1, path1), (name2, path2)) in paths1.iter().zip(paths2.iter()) {
        assert_eq!(name1, name2);
        let m1 = symlink_metadata(path1).unwrap();
        let m2 = symlink_metadata(path2).unwrap();
        assert_eq!(
            m1.file_type(),
            m2.file_type(),
            "file type mismatch ({name1})"
        );

        if m1.file_type().is_symlink() {
            let dst1 = read_link(path1).unwrap();
            let dst2 = read_link(path2).unwrap();
            assert_eq!(
                dst1, dst2,
                "symlink mismatch ({name1}): {:?}->{:?} vs {:?}->{:?}",
                path1, dst1, path2, dst2
            );
        } else {
            assert_eq!(m1.len(), m2.len(), "length mismatch ({name1})");
        }

        assert_eq!(
            m1.permissions(),
            m2.permissions(),
            "permissions mismatch ({name1})"
        );

        if m1.file_type().is_file() {
            let c1 = std::fs::read_to_string(path1).unwrap();
            let c2 = std::fs::read_to_string(path2).unwrap();
            assert_eq!(c1, c2, "content mismatch ({name1})");
        }
    }
}

#[test]
fn test_simple_dir() {
    // testdata
    // ├── a.txt
    // ├── b.txt
    // └── dir
    //     └── c.txt
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    create_dir(&dir).unwrap();
    File::create(dir.join("a.txt")).unwrap();
    File::create(dir.join("b.txt")).unwrap();
    create_dir(dir.join("dir")).unwrap();
    File::create(dir.join("dir/c.txt")).unwrap();
    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_nested_dirs() {
    // testdata
    // └── dir1
    //     ├── a.txt
    //     └── dir2
    //         ├── b.txt
    //         └── dir3
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    create_dir(&dir).unwrap();
    let dir1 = &dir.join("dir1");
    create_dir(dir1).unwrap();
    File::create(dir1.join("a.txt")).unwrap();
    let dir2 = dir1.join("dir2");
    create_dir(&dir2).unwrap();
    File::create(dir2.join("b.txt")).unwrap();
    let dir3 = dir2.join("dir3");
    create_dir(dir3).unwrap();
    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_file_contents() {
    // testdata
    // ├── hello.txt (content: "Hello!\n")
    // └── big.txt (content: 10KB of data, which doesn't fit in one block)
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    create_dir(&dir).unwrap();
    let mut hello = File::create(dir.join("hello.txt")).unwrap();
    hello.write_all(b"Hello!\n").unwrap();
    let mut big = BufWriter::new(File::create(dir.join("big.txt")).unwrap());
    let data = b"123456789\n";
    for _ in 0..1024 {
        big.write_all(data).unwrap();
    }

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_max_file_name() {
    // testdata
    // └── aa..aa (whose file name length is 255, which is the ext2/3/4's maximum file name length)
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    create_dir(&dir).unwrap();
    let long_name = "a".repeat(255);
    File::create(dir.join(long_name)).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_mkfs_indirect_block() {
    // testdata
    // ├── big.txt (80KiB), which requires indirect blocks
    // └── huge.txt (8MiB), which requires doubly indirect blocks
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    std::fs::create_dir(&dir).unwrap();
    let mut big = std::fs::File::create(dir.join("big.txt")).unwrap();
    big.seek(SeekFrom::Start(80 * 1024)).unwrap();
    big.write_all(&[0]).unwrap();

    let mut huge = std::fs::File::create(dir.join("huge.txt")).unwrap();
    huge.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
    huge.write_all(&[0]).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 4096,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_mkfs_symlink() {
    // testdata
    // ├── a.txt
    // ├── self -> ./self
    // ├── symlink0 -> ./a.txt
    // ├── symlink1 -> ./symlink0
    // └── dir
    //     └── upper-a -> ../a.txt
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");
    create_dir(&dir).unwrap();

    let mut f = File::create(dir.join("a.txt")).unwrap();
    f.write_all("Hello".as_bytes()).unwrap();

    symlink("./self", dir.join("self")).unwrap();

    symlink("./a.txt", dir.join("symlink0")).unwrap();
    symlink("./symlink0", dir.join("symlink1")).unwrap();

    create_dir(dir.join("dir")).unwrap();
    symlink("../a.txt", dir.join("dir/upper-a")).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_mkfs_abs_symlink() {
    // testdata
    // ├── a.txt
    // ├── a -> /testdata/a
    // ├── self -> /testdata/self
    // ├── tmp -> /tmp
    // └── abc -> /a/b/c
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");

    std::fs::create_dir(&dir).unwrap();
    File::create(dir.join("a.txt")).unwrap();
    symlink(dir.join("a.txt"), dir.join("a")).unwrap();
    symlink(dir.join("self"), dir.join("self")).unwrap();
    symlink("/tmp/", dir.join("tmp")).unwrap();
    symlink("/a/b/c", dir.join("abc")).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_mkfs_symlink_to_deleted() {
    // testdata
    // ├── (deleted)
    // └── symlink_to_deleted -> (deleted)
    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");

    std::fs::create_dir(&dir).unwrap();
    File::create(dir.join("deleted")).unwrap();
    symlink("./deleted", dir.join("symlink_to_deleted")).unwrap();
    fs::remove_file(dir.join("deleted")).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

#[test]
fn test_mkfs_long_symlink() {
    // testdata
    // ├── /(long name directory)/a.txt
    // └── symlink -> /(long name directory)/a.txt
    // ├── (60-byte filename)
    // └── symlink60 -> (60-byte filename)

    let td = tempdir().unwrap();
    let dir = td.path().join("testdata");

    create_dir(&dir).unwrap();

    const LONG_DIR_NAME: &str =
        "this_is_a_very_long_directory_name_so_that_name_cannoot_fit_in_60_characters_in_inode";
    assert!(LONG_DIR_NAME.len() > 60);

    let long_dir = dir.join(LONG_DIR_NAME);
    create_dir(&long_dir).unwrap();
    File::create(long_dir.join("a.txt")).unwrap();
    symlink(long_dir.join("a.txt"), dir.join("symlink")).unwrap();

    const SIXTY_CHAR_DIR_NAME: &str =
        "./this_is_just_60_byte_long_so_it_can_work_as_a_corner_case.";
    assert_eq!(SIXTY_CHAR_DIR_NAME.len(), 60);
    File::create(dir.join(SIXTY_CHAR_DIR_NAME)).unwrap();
    symlink(SIXTY_CHAR_DIR_NAME, dir.join("symlink60")).unwrap();

    let disk = mkfs(
        &td,
        &Config {
            blocks_per_group: 2048,
            inodes_per_group: 4096,
        },
        Some(&dir),
    );

    assert_eq_dirs(&td, &dir, &disk);
}

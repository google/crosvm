// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::path::Path;

use devices::virtio::fs::passthrough::Config;
use devices::virtio::fs::passthrough::Inode;
use devices::virtio::fs::passthrough::PassthroughFs;
use fuse::filesystem::Context;
use fuse::filesystem::FileSystem;
use fuse::filesystem::FsOptions;
use tempfile::TempDir;

/// Creates the given directories and files under `temp_dir`.
fn create_test_data(temp_dir: &TempDir, dirs: &[&str], files: &[&str]) {
    let path = temp_dir.path();

    for d in dirs {
        std::fs::create_dir_all(path.join(d)).unwrap();
    }

    for f in files {
        File::create(path.join(f)).unwrap();
    }
}

/// Looks up the given `path` in `fs`.
fn lookup(fs: &PassthroughFs, path: &Path) -> io::Result<Inode> {
    let mut inode = 1;
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 0,
    };
    for name in path.iter() {
        let name = CString::new(name.to_str().unwrap()).unwrap();
        let ent = match fs.lookup(ctx, inode, &name) {
            Ok(ent) => ent,
            Err(e) => {
                return Err(e);
            }
        };
        inode = ent.inode;
    }
    Ok(inode)
}

fn test_lookup() {
    let temp_dir = TempDir::new().unwrap();
    create_test_data(&temp_dir, &["dir"], &["a.txt", "dir/b.txt"]);

    let cfg = Default::default();
    let fs = PassthroughFs::new("tag", cfg).unwrap();

    let capable = FsOptions::empty();
    fs.init(capable).unwrap();

    assert!(lookup(&fs, &temp_dir.path().join("a.txt")).is_ok());
    assert!(lookup(&fs, &temp_dir.path().join("dir")).is_ok());
    assert!(lookup(&fs, &temp_dir.path().join("dir/b.txt")).is_ok());

    assert_eq!(
        lookup(&fs, &temp_dir.path().join("nonexistent-file"))
            .expect_err("file must not exist")
            .kind(),
        io::ErrorKind::NotFound
    );
    // "A.txt" is different from "a.txt".
    assert_eq!(
        lookup(&fs, &temp_dir.path().join("A.txt"))
            .expect_err("file must not exist")
            .kind(),
        io::ErrorKind::NotFound
    );
}

fn test_lookup_ascii_casefold() {
    let temp_dir = TempDir::new().unwrap();
    create_test_data(&temp_dir, &["dir"], &["a.txt", "dir/b.txt"]);

    let cfg = Config {
        ascii_casefold: true,
        ..Default::default()
    };
    let fs = PassthroughFs::new("tag", cfg).unwrap();

    let capable = FsOptions::empty();
    fs.init(capable).unwrap();

    // Ensure that "A.txt" is equated with "a.txt".
    let a_inode = lookup(&fs, &temp_dir.path().join("a.txt")).expect("a.txt must be found");
    assert_eq!(
        lookup(&fs, &temp_dir.path().join("A.txt")).expect("A.txt must exist"),
        a_inode
    );

    let dir_inode = lookup(&fs, &temp_dir.path().join("dir")).expect("dir must be found");
    assert_eq!(
        lookup(&fs, &temp_dir.path().join("DiR")).expect("DiR must exist"),
        dir_inode
    );

    let b_inode = lookup(&fs, &temp_dir.path().join("dir/b.txt")).expect("dir/b.txt must be found");
    assert_eq!(
        lookup(&fs, &temp_dir.path().join("dIr/B.TxT")).expect("dIr/B.TxT must exist"),
        b_inode
    );

    assert_eq!(
        lookup(&fs, &temp_dir.path().join("nonexistent-file"))
            .expect_err("file must not exist")
            .kind(),
        io::ErrorKind::NotFound
    );
}

pub fn main() {
    // Use `libtest_mimic` to force to run each test in single thread, as PassthroughFS can execute
    // process-wide fs operations such as fchdir.
    let args = libtest_mimic::Arguments {
        test_threads: Some(1),
        ..libtest_mimic::Arguments::from_args()
    };

    let tests = vec![
        libtest_mimic::Trial::test("test_lookup", move || {
            test_lookup();
            Ok(())
        }),
        libtest_mimic::Trial::test("test_lookup_ascii_casefold", move || {
            test_lookup_ascii_casefold();
            Ok(())
        }),
    ];
    libtest_mimic::run(&args, tests).exit();
}

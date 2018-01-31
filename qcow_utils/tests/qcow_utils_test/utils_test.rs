// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate tempdir;

use tempdir::TempDir;

use std::env::{current_exe, var_os};
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

fn get_crosvm_path() -> PathBuf {
    let mut crosvm_path = current_exe()
        .ok()
        .map(|mut path| {
            path.pop();
            path
        })
        .expect("failed to get crosvm binary directory");
    crosvm_path.push("crosvm");
    crosvm_path
}

fn build_test(src: &str) -> TempDir {
    let mut libqcow_utils = get_crosvm_path();
    libqcow_utils.set_file_name("libqcow_utils.so");

    let temp_dir = TempDir::new("qcow_util_test").expect("Failed to make temporary directory");
    let out_bin_file = PathBuf::from(temp_dir.path()).join("target");
    let mut child = Command::new(var_os("CC").unwrap_or(OsString::from("cc")))
        .args(&["-Isrc", "-pthread", "-o"])
        .arg(&out_bin_file)
        .arg(libqcow_utils)
        .args(&["-xc", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to spawn compiler");
    {
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(src.as_bytes())
            .expect("failed to write source to stdin");
    }

    let status = child.wait().expect("failed to wait for compiler");
    assert!(status.success(), "failed to build test");

    temp_dir
}

fn run_test(bin_path: &Path) {
    let mut child = Command::new(PathBuf::from(bin_path).join("target"))
        .spawn()
        .expect("failed to spawn test");
    for _ in 0..12 {
        match child.try_wait().expect("failed to wait for test") {
            Some(status) => {
                assert!(status.success(), "Test returned failure.");
                return;
            }
            None => sleep(Duration::from_millis(100)),
        }
    }
    child.kill().expect("failed to kill test");
    panic!("test subprocess has timed out");
}

pub fn run_c_test(src: &str) {
    let bin_path = build_test(src);
    run_test(bin_path.path());
}

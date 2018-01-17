// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(feature = "plugin")]

extern crate rand;

use rand::{thread_rng, Rng};

use std::ffi::OsString;
use std::fs::remove_file;
use std::io::Write;
use std::env::{current_exe, var_os};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

struct RemovePath(PathBuf);
impl Drop for RemovePath {
    fn drop(&mut self) {
        if let Err(e) = remove_file(&self.0) {
            eprintln!("failed to remove path: {:?}", e);
        }
    }
}

fn get_crosvm_path() -> PathBuf {
    let mut crosvm_path = current_exe()
        .ok()
        .map(|mut path| {
                 path.pop();
                 if path.ends_with("deps") {
                     path.pop();
                 }
                 path
             })
        .expect("failed to get crosvm binary directory");
    crosvm_path.push("crosvm");
    crosvm_path
}

fn build_plugin(src: &str) -> RemovePath {
    let mut out_bin = PathBuf::from("target");
    let mut libcrosvm_plugin = get_crosvm_path();
    libcrosvm_plugin.set_file_name("libcrosvm_plugin.so");
    out_bin.push(thread_rng()
                     .gen_ascii_chars()
                     .take(10)
                     .collect::<String>());
    let mut child = Command::new(var_os("CC").unwrap_or(OsString::from("cc")))
        .args(&["-Icrosvm_plugin", "-pthread", "-o"])
        .arg(&out_bin)
        .arg(libcrosvm_plugin)
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
    assert!(status.success(), "failed to build plugin");

    RemovePath(PathBuf::from(out_bin))
}

fn run_plugin(bin_path: &Path) {
    let mut child = Command::new(get_crosvm_path())
        .args(&["run", "-c", "1", "--plugin"])
        .arg(bin_path)
        .spawn()
        .expect("failed to spawn crosvm");
    for _ in 0..12 {
        match child.try_wait().expect("failed to wait for crosvm") {
            Some(status) => {
                assert!(status.success());
                return;
            }
            None => sleep(Duration::from_millis(100)),
        }
    }
    child.kill().expect("failed to kill crosvm");
    panic!("crosvm process has timed out");
}

fn test_plugin(src: &str) {
    let bin_path = build_plugin(src);
    run_plugin(&bin_path.0);
}

#[test]
fn test_adder() {
    test_plugin(include_str!("plugin_adder.c"));
}

#[test]
fn test_dirty_log() {
    test_plugin(include_str!("plugin_dirty_log.c"));
}

#[test]
fn test_ioevent() {
    test_plugin(include_str!("plugin_ioevent.c"));
}

#[test]
fn test_irqfd() {
    test_plugin(include_str!("plugin_irqfd.c"));
}

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

fn get_target_path() -> PathBuf {
    current_exe()
        .ok()
        .map(|mut path| {
                 path.pop();
                 if path.ends_with("deps") {
                     path.pop();
                 }
                 path
             })
        .expect("failed to get crosvm binary directory")
}

fn build_plugin(src: &str) -> RemovePath {
    let mut out_bin = PathBuf::from("target");
    let libcrosvm_plugin_dir = get_target_path();
    out_bin.push(thread_rng()
                     .gen_ascii_chars()
                     .take(10)
                     .collect::<String>());
    let mut child = Command::new(var_os("CC").unwrap_or(OsString::from("cc")))
        .args(&["-Icrosvm_plugin", "-pthread", "-o"]) // crosvm.h location and set output path.
        .arg(&out_bin)
        .arg("-L") // Path of shared object to link to.
        .arg(&libcrosvm_plugin_dir)
        .arg("-lcrosvm_plugin")
        .arg("-Wl,-rpath") // Search for shared object in the same path when exec'd.
        .arg(&libcrosvm_plugin_dir)
        .args(&["-Wl,-rpath", "."]) // Also check current directory in case of sandboxing.
        .args(&["-xc", "-"]) // Read source code from piped stdin.
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

fn run_plugin(bin_path: &Path, with_sandbox: bool) {
    let mut crosvm_path = get_target_path();
    crosvm_path.push("crosvm");
    let mut cmd = Command::new(crosvm_path);
    cmd.args(&["run",
                "-c",
                "1",
                "--seccomp-policy-dir",
                "tests",
                "--plugin"])
        .arg(bin_path
                 .canonicalize()
                 .expect("failed to canonicalize plugin path"));
    if !with_sandbox {
        cmd.arg("--disable-sandbox");
    }

    let mut child = cmd
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
    // Run with and without the sandbox enabled.
    run_plugin(&bin_path.0, false);
    run_plugin(&bin_path.0, true);
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

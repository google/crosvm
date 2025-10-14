// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utility functions used by multiple fixture files.

use std::env;
use std::io::ErrorKind;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::Result;
use tempfile::NamedTempFile;

use crate::sys::binary_name;
use crate::vhost_user::CmdType;
use crate::vhost_user::Config as VuConfig;

pub const DEFAULT_BLOCK_SIZE: u64 = 1024 * 1024;

/// Returns the path to the crosvm binary to be tested.
///
/// It checks multiple paths so that it supports multiple ways of executing tests.
pub fn find_crosvm_binary() -> PathBuf {
    let binary_name = binary_name();
    // When e2e tests are run via tools/run_tests, the crosvm binary is copied to `bin` directory
    // under `CARGO_MANIFEST_DIR`.
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let bin_crosvm = PathBuf::from(cargo_manifest_dir)
        .parent()
        .unwrap()
        .join("bin")
        .join(binary_name);
    if bin_crosvm.exists() {
        return bin_crosvm;
    }

    // When `cargo test -p e2e_tests` is called directly, the crosvm binary is in target/debug while
    // the test binary is in target/debug/deps/.
    let exe_dir = env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let parent_dir_crosvm = exe_dir.parent().unwrap().join(binary_name);
    if parent_dir_crosvm.exists() {
        return parent_dir_crosvm;
    }

    panic!(
        "Cannot find {} either in {} or {}.",
        binary_name,
        bin_crosvm.display(),
        parent_dir_crosvm.display()
    );
}

/// Run the provided closure in a separate thread and return it's result. If the closure does not
/// finish before the timeout is reached, an Error is returned instead.
///
/// WARNING: It is not possible to kill the closure if a timeout occurs. It is advised to panic
/// when an error is returned.
pub fn run_with_timeout<F, U>(closure: F, timeout: Duration) -> Result<U>
where
    F: FnOnce() -> U + Send + 'static,
    U: Send + 'static,
{
    run_with_status_check(closure, timeout, || false)
}

/// Run the provided closure in a separate thread and return it's result. If the closure does not
/// finish, continue_fn is called periodically with interval while continue_fn return true. Once
/// continue_fn return false, an Error is returned instead.
///
/// WARNING: It is not possible to kill the closure if a timeout occurs. It is advised to panic
/// when an error is returned.
pub fn run_with_status_check<F, U, C>(
    closure: F,
    interval: Duration,
    mut continue_fn: C,
) -> Result<U>
where
    F: FnOnce() -> U + Send + 'static,
    U: Send + 'static,
    C: FnMut() -> bool,
{
    let (tx, rx) = sync_channel::<()>(1);
    let handle = thread::spawn(move || {
        let result = closure();
        // Notify main thread the closure is done. Fail silently if it's not listening anymore.
        let _ = tx.send(());
        result
    });
    loop {
        match rx.recv_timeout(interval) {
            Ok(_) => {
                return Ok(handle.join().unwrap());
            }
            Err(RecvTimeoutError::Timeout) => {
                if !continue_fn() {
                    bail!("closure timed out");
                }
            }
            Err(RecvTimeoutError::Disconnected) => bail!("closure panicked"),
        }
    }
}

#[derive(Debug)]
pub enum CommandError {
    IoError(std::io::Error),
    ErrorCode(i32),
    Signal(i32),
}

/// Extension trait for utilities on std::process::Command
pub trait CommandExt {
    /// Same as Command::output() but will treat non-success status of the Command as an
    /// error.
    fn output_checked(&mut self) -> std::result::Result<Output, CommandError>;

    /// Print the command to be executed
    fn log(&mut self) -> &mut Self;
}

impl CommandExt for Command {
    fn output_checked(&mut self) -> std::result::Result<Output, CommandError> {
        let output = self.output().map_err(CommandError::IoError)?;
        if !output.status.success() {
            if let Some(code) = output.status.code() {
                return Err(CommandError::ErrorCode(code));
            } else {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                if let Some(signal) = output.status.signal() {
                    return Err(CommandError::Signal(signal));
                }
                panic!("No error code and no signal should never happen.");
            }
        }
        Ok(output)
    }

    fn log(&mut self) -> &mut Self {
        println!("$ {:?}", self);
        self
    }
}

/// Extension trait for utilities on std::process::Child
pub trait ChildExt {
    /// Same as Child.wait(), but will return with an error after the specified timeout.
    fn wait_with_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<ExitStatus>>;
}

impl ChildExt for std::process::Child {
    fn wait_with_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
        let start_time = SystemTime::now();
        while SystemTime::now().duration_since(start_time).unwrap() < timeout {
            if let Ok(status) = self.try_wait() {
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "Timeout while waiting for child",
        ))
    }
}

/// Calls the `closure` until it returns a non-error Result.
/// If it has been re-tried `retries` times, the last result is returned.
pub fn retry<F, T, E>(closure: F, retries: usize) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Debug,
{
    retry_with_delay(closure, retries, Duration::ZERO)
}

/// Calls the `closure` until it returns a non-error Result.
/// If it has been re-tried `retries` times, the last result is returned.
/// Waits `delay` between attempts.
pub fn retry_with_delay<F, T, E>(mut closure: F, retries: usize, delay: Duration) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: std::fmt::Debug,
{
    let mut attempts_left = retries + 1;
    loop {
        let result = closure();
        attempts_left -= 1;
        if result.is_ok() || attempts_left == 0 {
            break result;
        } else {
            println!("Attempt failed: {:?}", result.err());
            std::thread::sleep(delay);
        }
    }
}

/// Prepare a temporary ext4 disk file.
pub fn prepare_disk_img() -> NamedTempFile {
    let mut disk = NamedTempFile::new().unwrap();
    disk.as_file_mut().set_len(DEFAULT_BLOCK_SIZE).unwrap();

    // Add /sbin and /usr/sbin to PATH since some distributions put mkfs.ext4 in one of those
    // directories but don't add them to non-root PATH.
    let path = env::var("PATH").unwrap();
    let path = [&path, "/sbin", "/usr/sbin"].join(":");

    // TODO(b/243127910): Use `mkfs.ext4 -d` to include test data.
    Command::new("mkfs.ext4")
        .arg(disk.path().to_str().unwrap())
        .env("PATH", path)
        .output()
        .expect("failed to execute process");
    disk
}

pub fn create_vu_block_config(cmd_type: CmdType, socket: &Path, disk: &Path) -> VuConfig {
    let socket_path = socket.to_str().unwrap();
    let disk_path = disk.to_str().unwrap();
    println!("disk={disk_path}, socket={socket_path}");
    match cmd_type {
        CmdType::Device => VuConfig::new(cmd_type, "block").extra_args(vec![
            "block".to_string(),
            "--socket-path".to_string(),
            socket_path.to_string(),
            "--file".to_string(),
            disk_path.to_string(),
        ]),
        CmdType::Devices => VuConfig::new(cmd_type, "block").extra_args(vec![
            "--block".to_string(),
            format!("vhost={},path={}", socket_path, disk_path),
        ]),
    }
}

pub fn create_vu_console_multiport_config(
    socket: &Path,
    file_path: Vec<(PathBuf, PathBuf)>,
) -> VuConfig {
    let socket_path = socket.to_str().unwrap();

    let mut args = vec![
        "console".to_string(),
        "--socket-path".to_string(),
        socket_path.to_string(),
    ];

    for (i, (output_file, input_file)) in file_path.iter().enumerate() {
        args.push("--port".to_string());
        match input_file.file_name().is_some() {
            true => {
                args.push(format!(
                    "type=file,hardware=virtio-console,name=port{},path={},input={}",
                    i,
                    output_file.to_str().unwrap(),
                    input_file.to_str().unwrap(),
                ));
            }
            false => {
                args.push(format!(
                    "type=file,hardware=virtio-console,name=port{},path={}",
                    i,
                    output_file.to_str().unwrap(),
                ));
            }
        };
    }
    VuConfig::new(CmdType::Device, "console").extra_args(args)
}

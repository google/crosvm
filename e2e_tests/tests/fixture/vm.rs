// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::io::BufRead;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str::from_utf8;
use std::sync::mpsc::sync_channel;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use base::syslog;
use prebuilts::download_file;

use crate::fixture::sys::SerialArgs;
use crate::fixture::sys::TestVmSys;

const PREBUILT_URL: &str = "https://storage.googleapis.com/crosvm/integration_tests";

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "arm")]
const ARCH: &str = "arm";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

fn prebuilt_version() -> &'static str {
    include_str!("../../guest_under_test/PREBUILT_VERSION").trim()
}

fn kernel_prebuilt_url() -> String {
    format!(
        "{}/guest-bzimage-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    )
}

fn rootfs_prebuilt_url() -> String {
    format!(
        "{}/guest-rootfs-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    )
}

/// The kernel bzImage is stored next to the test executable, unless overridden by
/// CROSVM_CARGO_TEST_KERNEL_BINARY
pub(super) fn kernel_path() -> PathBuf {
    match env::var("CROSVM_CARGO_TEST_KERNEL_BINARY") {
        Ok(value) => PathBuf::from(value),
        Err(_) => env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("bzImage"),
    }
}

/// The rootfs image is stored next to the test executable, unless overridden by
/// CROSVM_CARGO_TEST_ROOTFS_IMAGE
pub(super) fn rootfs_path() -> PathBuf {
    match env::var("CROSVM_CARGO_TEST_ROOTFS_IMAGE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => env::current_exe().unwrap().parent().unwrap().join("rootfs"),
    }
}

/// Run the provided closure, but panic if it does not complete until the timeout has passed.
/// We should panic here, as we cannot gracefully stop the closure from running.
/// `on_timeout` will be called before panic to allow printing debug information.
pub(super) fn run_with_timeout<F, G, U>(closure: F, timeout: Duration, on_timeout: G) -> U
where
    F: FnOnce() -> U + Send + 'static,
    G: FnOnce(),
    U: Send + 'static,
{
    let (tx, rx) = sync_channel::<()>(1);
    let handle = thread::spawn(move || {
        let result = closure();
        tx.send(()).unwrap();
        result
    });
    if rx.recv_timeout(timeout).is_err() {
        on_timeout();
        panic!("Operation timed out or closure paniced.");
    }
    handle.join().unwrap()
}

/// Configuration to start `TestVm`.
#[derive(Default)]
pub struct Config {
    /// Extra arguments for the `run` subcommand.
    pub(super) extra_args: Vec<String>,

    /// Use `O_DIRECT` for the rootfs.
    pub(super) o_direct: bool,
}

#[cfg(test)]
impl Config {
    /// Creates a new `run` command with `extra_args`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Uses extra arguments for `crosvm run`.
    #[allow(dead_code)]
    pub fn extra_args(mut self, args: Vec<String>) -> Self {
        let mut args = args;
        self.extra_args.append(&mut args);
        self
    }

    /// Uses `O_DIRECT` for the rootfs.
    pub fn o_direct(mut self) -> Self {
        self.o_direct = true;
        self
    }

    /// Uses `disable-sandbox` argument for `crosvm run`.
    pub fn disable_sandbox(mut self) -> Self {
        self.extra_args.push("--disable-sandbox".to_string());
        self
    }
}

static PREP_ONCE: Once = Once::new();

/// Test fixture to spin up a VM running a guest that can be communicated with.
///
/// After creation, commands can be sent via exec_in_guest. The VM is stopped
/// when this instance is dropped.
#[cfg(test)]
pub struct TestVm {
    sys: TestVmSys,
}

impl TestVm {
    /// Magic line sent by the delegate binary when the guest is ready.
    pub(super) const MAGIC_LINE: &'static str = "\x05Ready";

    /// Downloads prebuilts if needed.
    fn initialize_once() {
        if let Err(e) = syslog::init() {
            panic!("failed to initiailize syslog: {}", e);
        }

        // It's possible the prebuilts downloaded by crosvm-9999.ebuild differ
        // from the version that crosvm was compiled for.
        if let Ok(value) = env::var("CROSVM_CARGO_TEST_PREBUILT_VERSION") {
            if value != prebuilt_version() {
                panic!(
                    "Environment provided prebuilts are version {}, but crosvm was compiled \
                    for prebuilt version {}. Did you update PREBUILT_VERSION everywhere?",
                    value,
                    prebuilt_version()
                );
            }
        }

        let kernel_path = kernel_path();
        if env::var("CROSVM_CARGO_TEST_KERNEL_BINARY").is_err() {
            if !kernel_path.exists() {
                download_file(&kernel_prebuilt_url(), &kernel_path).unwrap();
            }
        }
        assert!(kernel_path.exists(), "{:?} does not exist", kernel_path);

        let rootfs_path = rootfs_path();
        if env::var("CROSVM_CARGO_TEST_ROOTFS_IMAGE").is_err() {
            if !rootfs_path.exists() {
                download_file(&rootfs_prebuilt_url(), &rootfs_path).unwrap();
            }
        }
        assert!(rootfs_path.exists(), "{:?} does not exist", rootfs_path);

        TestVmSys::check_rootfs_file(&rootfs_path);
    }

    /// Instanciate a new crosvm instance. The first call will trigger the download of prebuilt
    /// files if necessary.
    ///
    /// This generic method takes a `FnOnce` argument which is in charge of completing the `Command`
    /// with all the relevant options needed to boot the VM.
    pub fn new_generic<F>(f: F, cfg: Config) -> Result<TestVm>
    where
        F: FnOnce(&mut Command, &SerialArgs, &Config) -> Result<()>,
    {
        PREP_ONCE.call_once(TestVm::initialize_once);

        Ok(TestVm {
            sys: TestVmSys::new_generic(f, cfg)?,
        })
    }

    pub fn new(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(TestVmSys::append_config_args, cfg)
    }

    /// Instanciate a new crosvm instance using a configuration file. The first call will trigger
    /// the download of prebuilt files if necessary.
    pub fn new_with_config_file(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(TestVmSys::append_config_file_arg, cfg)
    }

    /// Executes the shell command `command` and returns the programs stdout.
    pub fn exec_in_guest(&mut self, command: &str) -> Result<String> {
        self.exec_command(command)?;
        self.wait_for_guest()
    }

    pub fn exec_command(&mut self, command: &str) -> Result<()> {
        // Write command to serial port.
        writeln!(&mut self.sys.to_guest, "{}", command)?;

        // We will receive an echo of what we have written on the pipe.
        let mut echo = String::new();
        self.sys.from_guest_reader.read_line(&mut echo)?;
        assert_eq!(echo.trim(), command);
        Ok(())
    }

    /// Executes the shell command `command` async, allowing for calls other actions between the
    /// command call and the result, and returns the programs stdout.
    pub fn exec_command_async(&mut self, command: &str, block: impl Fn(&mut Self)) -> Result<()> {
        // Write command to serial port.
        writeln!(&mut self.sys.to_guest, "{}", command)?;
        block(self);
        let mut echo = String::new();
        self.sys.from_guest_reader.read_line(&mut echo)?;
        assert_eq!(echo.trim(), command);
        Ok(())
    }

    pub fn wait_for_guest(&mut self) -> Result<String> {
        // Return all remaining lines until we receive the MAGIC_LINE
        let mut output = String::new();
        loop {
            let mut line = String::new();
            self.sys.from_guest_reader.read_line(&mut line)?;
            if line.trim() == TestVm::MAGIC_LINE {
                break;
            }
            output.push_str(&line);
        }
        let trimmed = output.trim();
        println!("<- {:?}", trimmed);

        Ok(trimmed.to_string())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.sys.crosvm_command("stop", vec![])
    }

    pub fn suspend(&mut self) -> Result<()> {
        self.sys.crosvm_command("suspend", vec![])
    }

    pub fn resume(&mut self) -> Result<()> {
        self.sys.crosvm_command("resume", vec![])
    }

    pub fn disk(&mut self, args: Vec<String>) -> Result<()> {
        self.sys.crosvm_command("disk", args)
    }

    pub fn snapshot(&mut self, filename: &std::path::Path) -> Result<()> {
        self.sys.crosvm_command(
            "snapshot",
            vec!["take".to_string(), String::from(filename.to_str().unwrap())],
        )
    }

    // No argument is passed in restore as we will always restore snapshot.bkp for testing.
    pub fn restore(&mut self, filename: &std::path::Path) -> Result<()> {
        self.sys.crosvm_command(
            "snapshot",
            vec![
                "restore".to_string(),
                String::from(filename.to_str().unwrap()),
            ],
        )
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        self.stop().unwrap();
        let output = self.sys.process.take().unwrap().wait_with_output().unwrap();

        // Print both the crosvm's stdout/stderr to stdout so that they'll be shown when the test
        // failed.
        println!("TestVm stdout:\n{}", from_utf8(&output.stdout).unwrap());
        println!("TestVm stderr:\n{}", from_utf8(&output.stderr).unwrap());

        if !output.status.success() {
            panic!("VM exited illegally: {}", output.status);
        }
    }
}

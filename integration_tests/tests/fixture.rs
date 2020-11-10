// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::sync_channel;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use arch::{set_default_serial_parameters, SerialHardware, SerialParameters, SerialType};
use base::syslog;
use crosvm::{platform, Config, DiskOption, Executable};
use tempfile::TempDir;

const PREBUILT_URL: &str = "https://storage.googleapis.com/chromeos-localmirror/distfiles";

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "arm")]
const ARCH: &str = "arm";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

/// Timeout for communicating with the VM. If we do not hear back, panic so we
/// do not block the tests.
const VM_COMMUNICATION_TIMEOUT: Duration = Duration::from_millis(1000);

fn prebuilt_version() -> &'static str {
    include_str!("../guest_under_test/PREBUILT_VERSION").trim()
}

fn kernel_prebuilt_url() -> String {
    format!(
        "{}/crosvm-testing-bzimage-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    )
}

fn rootfs_prebuilt_url() -> String {
    format!(
        "{}/crosvm-testing-rootfs-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    )
}

/// The kernel bzImage is stored next to the test executable, unless overridden by
/// CROSVM_CARGO_TEST_KERNEL_BINARY
fn kernel_path() -> PathBuf {
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
fn rootfs_path() -> PathBuf {
    match env::var("CROSVM_CARGO_TEST_ROOTFS_IMAGE") {
        Ok(value) => PathBuf::from(value),
        Err(_) => env::current_exe().unwrap().parent().unwrap().join("rootfs"),
    }
}

/// Safe wrapper for libc::mkfifo
fn mkfifo(path: &Path) -> io::Result<()> {
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let result = unsafe { libc::mkfifo(cpath.as_ptr(), 0o777) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Run the provided closure, but panic if it does not complete until the timeout has passed.
/// We should panic here, as we cannot gracefully stop the closure from running.
fn panic_on_timeout<F, U>(closure: F, timeout: Duration) -> U
where
    F: FnOnce() -> U + Send + 'static,
    U: Send + 'static,
{
    let (tx, rx) = sync_channel::<()>(1);
    let handle = thread::spawn(move || {
        let result = closure();
        tx.send(()).unwrap();
        result
    });
    rx.recv_timeout(timeout)
        .expect("Operation timed out or closure paniced.");
    handle.join().unwrap()
}

fn download_file(url: &str, destination: &Path) -> Result<()> {
    let status = Command::new("curl")
        .arg("--fail")
        .arg("--location")
        .args(&["--output", destination.to_str().unwrap()])
        .arg(url)
        .status();
    match status {
        Ok(exit_code) => {
            if !exit_code.success() {
                Err(anyhow!("Cannot download {}", url))
            } else {
                Ok(())
            }
        }
        Err(error) => Err(anyhow!(error)),
    }
}

#[derive(Default)]
pub struct TestVmOptions {
    pub debug: bool,
}

/// Test fixture to spin up a VM running a guest that can be communicated with.
///
/// After creation, commands can be sent via exec_in_guest. The VM is stopped
/// when this instance is dropped.
pub struct TestVm {
    /// Maintain ownership of test_dir until the vm is destroyed.
    #[allow(dead_code)]
    test_dir: TempDir,
    from_guest_reader: BufReader<File>,
    to_guest: File,
    vm_thread: Option<thread::JoinHandle<()>>,
    options: TestVmOptions,
}

impl TestVm {
    /// Magic line sent by the delegate binary when the guest is ready.
    const MAGIC_LINE: &'static str = "\x05Ready";

    /// Downloads prebuilts if needed.
    fn initialize_once() {
        syslog::init().unwrap();

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
                println!("Downloading kernel prebuilt:");
                download_file(&kernel_prebuilt_url(), &kernel_path).unwrap();
            }
        }
        assert!(kernel_path.exists(), "{:?} does not exist", kernel_path);

        let rootfs_path = rootfs_path();
        if env::var("CROSVM_CARGO_TEST_ROOTFS_IMAGE").is_err() {
            if !rootfs_path.exists() {
                println!("Downloading rootfs prebuilt:");
                download_file(&rootfs_prebuilt_url(), &rootfs_path).unwrap();
            }
        }
        assert!(rootfs_path.exists(), "{:?} does not exist", rootfs_path);
    }

    // Adds 2 serial devices:
    // - ttyS0: Console device which prints kernel log / debug output of the
    //          delegate binary.
    // - ttyS1: Serial device attached to the named pipes.
    fn configure_serial_devices(
        config: &mut Config,
        from_guest_pipe: &Path,
        to_guest_pipe: &Path,
        debug: bool,
    ) -> Result<()> {
        for ((_, index), _) in &config.serial_parameters {
            if *index == 1 || *index == 2 {
                return Err(anyhow!("Do not specify serial device 1 or 2."));
            }
        }

        config.serial_parameters.insert(
            (SerialHardware::Serial, 1),
            SerialParameters {
                type_: if debug {
                    SerialType::Stdout
                } else {
                    SerialType::Sink
                },
                hardware: SerialHardware::Serial,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: false,
            },
        );
        config.serial_parameters.insert(
            (SerialHardware::Serial, 2),
            SerialParameters {
                type_: SerialType::File,
                hardware: SerialHardware::Serial,
                path: Some(PathBuf::from(from_guest_pipe)),
                input: Some(PathBuf::from(to_guest_pipe.clone())),
                num: 2,
                console: false,
                earlycon: false,
                stdin: false,
            },
        );
        set_default_serial_parameters(&mut config.serial_parameters);
        return Ok(());
    }

    /// Configures the VM kernel and rootfs to load from the guest_under_test assets.
    fn configure_kernel(config: &mut Config) -> Result<()> {
        for param in &config.params {
            if param.starts_with("root") || param.starts_with("init") {
                return Err(anyhow!("Do not set the root or init parameters."));
            }
        }
        config.executable_path = Some(Executable::Kernel(kernel_path()));
        config.params.push("root=/dev/vda ro".to_string());
        config.params.push("init=/bin/delegate".to_string());
        config.disks.insert(
            0,
            DiskOption {
                id: None,
                path: rootfs_path(),
                read_only: true,
                sparse: true,
                block_size: 512,
            },
        );

        return Ok(());
    }

    /// Instanciate a new crosvm instance. The first call will trigger the download of prebuilt
    /// files if necessary.
    pub fn new(mut config: Config, options: TestVmOptions) -> Result<TestVm> {
        static PREP_ONCE: Once = Once::new();
        PREP_ONCE.call_once(|| TestVm::initialize_once());

        // TODO(b/173233134): Running sandboxed tests is going to require a lot of configuration
        // on the host.
        config.sandbox = false;

        // Create two named pipes to communicate with the guest.
        let test_dir = TempDir::new()?;
        let from_guest_pipe = test_dir.path().join("from_guest");
        let to_guest_pipe = test_dir.path().join("to_guest");
        mkfifo(&from_guest_pipe)?;
        mkfifo(&to_guest_pipe)?;

        TestVm::configure_serial_devices(
            &mut config,
            &from_guest_pipe,
            &to_guest_pipe,
            options.debug,
        )?;
        TestVm::configure_kernel(&mut config)?;

        // Run VM in a separate thread.
        let vm_thread = thread::spawn(move || {
            platform::run_config(config).expect("Cannot run VM.");
        });

        // Open pipes. Panic if we cannot connect after a timeout.
        let (to_guest, from_guest) = panic_on_timeout(
            move || (File::create(to_guest_pipe), File::open(from_guest_pipe)),
            VM_COMMUNICATION_TIMEOUT,
        );

        // Wait for magic line to be received, indicating the delegate is ready.
        let mut from_guest_reader = BufReader::new(from_guest?);
        let mut magic_line = String::new();
        from_guest_reader.read_line(&mut magic_line)?;
        assert_eq!(magic_line.trim(), TestVm::MAGIC_LINE);

        Ok(TestVm {
            test_dir,
            from_guest_reader,
            to_guest: to_guest?,
            vm_thread: Some(vm_thread),
            options,
        })
    }

    /// Executes the shell command `command` and returns the programs stdout.
    pub fn exec_in_guest(&mut self, command: &str) -> Result<String> {
        // Write command to serial port.
        writeln!(&mut self.to_guest, "{}", command)?;

        // We will receive an echo of what we have written on the pipe.
        let mut echo = String::new();
        self.from_guest_reader.read_line(&mut echo)?;
        assert_eq!(echo.trim(), command);

        // Return all remaining lines until we receive the MAGIC_LINE
        let mut output = String::new();
        loop {
            let mut line = String::new();
            self.from_guest_reader.read_line(&mut line)?;
            if line.trim() == TestVm::MAGIC_LINE {
                break;
            }
            output.push_str(&line);
        }
        let trimmed = output.trim();
        if self.options.debug {
            println!("<- {:?}", trimmed);
        }
        Ok(trimmed.to_string())
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        if let Some(handle) = self.vm_thread.take() {
            // Run exit command to shut down the VM.
            writeln!(&mut self.to_guest, "exit").expect("Cannot send exit command.");
            // Wait for the VM to exit, but don't wait forever.
            panic_on_timeout(
                move || {
                    handle.join().expect("Cannot join VM thread.");
                },
                VM_COMMUNICATION_TIMEOUT,
            );
        }
    }
}

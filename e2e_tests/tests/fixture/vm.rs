// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::str::from_utf8;
use std::sync::mpsc::sync_channel;
use std::sync::Once;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;
use base::syslog;
use libc::O_DIRECT;
use tempfile::TempDir;

use crate::fixture::utils::find_crosvm_binary;

const PREBUILT_URL: &str = "https://storage.googleapis.com/crosvm/integration_tests";

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "arm")]
const ARCH: &str = "arm";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

/// Timeout for communicating with the VM. If we do not hear back, panic so we
/// do not block the tests.
const VM_COMMUNICATION_TIMEOUT: Duration = Duration::from_secs(10);

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
/// `on_timeout` will be called before panic to allow printing debug information.
fn run_with_timeout<F, G, U>(closure: F, timeout: Duration, on_timeout: G) -> U
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

/// Configuration to start `TestVm`.
#[derive(Default)]
pub struct Config {
    /// Extra arguments for the `run` subcommand.
    extra_args: Vec<String>,

    /// Use `O_DIRECT` for the rootfs.
    o_direct: bool,
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
        self.extra_args = args;
        self
    }

    /// Uses `O_DIRECT` for the rootfs.
    pub fn o_direct(mut self) -> Self {
        self.o_direct = true;
        self
    }
}

static PREP_ONCE: Once = Once::new();
const FROM_GUEST_PIPE: &str = "from_guest";
const TO_GUEST_PIPE: &str = "to_guest";
const CONTROL_PIPE: &str = "control";
const VM_JSON_CONFIG_FILE: &str = "vm.json";

/// Test fixture to spin up a VM running a guest that can be communicated with.
///
/// After creation, commands can be sent via exec_in_guest. The VM is stopped
/// when this instance is dropped.
#[cfg(test)]
pub struct TestVm {
    /// Maintain ownership of test_dir until the vm is destroyed.
    #[allow(dead_code)]
    test_dir: TempDir,
    from_guest_reader: BufReader<File>,
    to_guest: File,
    control_socket_path: PathBuf,
    process: Option<Child>, // Use `Option` to allow taking the ownership in `Drop::drop()`.
}

impl TestVm {
    /// Magic line sent by the delegate binary when the guest is ready.
    const MAGIC_LINE: &'static str = "\x05Ready";

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

        // Check if the test file system is a known compatible one. Needs to support features like O_DIRECT.
        if let Err(e) = OpenOptions::new()
            .custom_flags(O_DIRECT)
            .write(false)
            .read(true)
            .open(rootfs_path)
        {
            panic!(
                "File open with O_DIRECT expected to work but did not: {}",
                e
            );
        }
    }

    // Adds 2 serial devices:
    // - ttyS0: Console device which prints kernel log / debug output of the
    //          delegate binary.
    // - ttyS1: Serial device attached to the named pipes.
    fn configure_serial_devices(
        command: &mut Command,
        from_guest_pipe: &Path,
        to_guest_pipe: &Path,
    ) {
        command.args(&["--serial", "type=syslog"]);

        // Setup channel for communication with the delegate.
        let serial_params = format!(
            "type=file,path={},input={},num=2",
            from_guest_pipe.display(),
            to_guest_pipe.display()
        );
        command.args(&["--serial", &serial_params]);
    }

    /// Configures the VM rootfs to load from the guest_under_test assets.
    fn configure_rootfs(command: &mut Command, o_direct: bool) {
        let rootfs_and_option = format!(
            "{}{},ro,root",
            rootfs_path().to_str().unwrap(),
            if o_direct { ",direct=true" } else { "" }
        );
        command
            .args(&["--block", &rootfs_and_option])
            .args(&["--params", "init=/bin/delegate"]);
    }

    /// Instanciate a new crosvm instance. The first call will trigger the download of prebuilt
    /// files if necessary.
    ///
    /// This generic method takes a `FnOnce` argument which is in charge of completing the `Command`
    /// with all the relevant options needed to boot the VM.
    pub fn new_generic<F>(f: F, cfg: Config) -> Result<TestVm>
    where
        F: FnOnce(&mut Command, &Path, &Config) -> Result<()>,
    {
        PREP_ONCE.call_once(TestVm::initialize_once);

        // Create two named pipes to communicate with the guest.
        let test_dir = TempDir::new()?;
        let from_guest_pipe = test_dir.path().join(FROM_GUEST_PIPE);
        let to_guest_pipe = test_dir.path().join(TO_GUEST_PIPE);
        mkfifo(&from_guest_pipe)?;
        mkfifo(&to_guest_pipe)?;

        let control_socket_path = test_dir.path().join(CONTROL_PIPE);

        let mut command = Command::new(find_crosvm_binary());
        command.args(&["run"]);

        f(&mut command, test_dir.path(), &cfg)?;

        command.args(&cfg.extra_args);
        // Set `Stdio::piped` so we can forward the outputs to stdout later.
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        println!("$ {:?}", command);

        let mut process = Some(command.spawn()?);

        // Open pipes. Panic if we cannot connect after a timeout.
        let (to_guest, from_guest) = run_with_timeout(
            move || (File::create(to_guest_pipe), File::open(from_guest_pipe)),
            VM_COMMUNICATION_TIMEOUT,
            || {
                let mut process = process.take().unwrap();
                process.kill().unwrap();
                let output = process.wait_with_output().unwrap();

                // Print both the crosvm's stdout/stderr to stdout so that they'll be shown when
                // the test failed.
                println!(
                    "TestVm stdout:\n{}",
                    std::str::from_utf8(&output.stdout).unwrap()
                );
                println!(
                    "TestVm stderr:\n{}",
                    std::str::from_utf8(&output.stderr).unwrap()
                );
            },
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
            control_socket_path,
            process,
        })
    }

    pub fn new(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(
            |command, test_dir, cfg| {
                TestVm::configure_serial_devices(
                    command,
                    &test_dir.join(FROM_GUEST_PIPE),
                    &test_dir.join(TO_GUEST_PIPE),
                );
                command.args(&["--socket", test_dir.join(CONTROL_PIPE).to_str().unwrap()]);
                TestVm::configure_rootfs(command, cfg.o_direct);
                // Set kernel as the last argument.
                command.arg(kernel_path());

                Ok(())
            },
            cfg,
        )
    }

    /// Generate a JSON configuration file for `cfg` and returns its path.
    fn generate_json_config_file(test_dir: &Path, cfg: &Config) -> Result<PathBuf> {
        let config_file_path = test_dir.join(VM_JSON_CONFIG_FILE);
        let mut config_file = File::create(&config_file_path)?;

        writeln!(
            config_file,
            r#"
            {{
              "kernel": "{}",
              "socket": "{}",
              "params": [ "init=/bin/delegate" ],
              "serial": [
                {{
                  "type": "syslog"
                }},
                {{
                  "type": "file",
                  "path": "{}",
                  "input": "{}",
                  "num": 2
                }}
              ],
              "block": [
                {{
                  "path": "{}",
                  "ro": true,
                  "root": true,
                  "direct": {}
                }}
              ]
            }}
            "#,
            kernel_path().display(),
            test_dir.join(CONTROL_PIPE).display(),
            test_dir.join(FROM_GUEST_PIPE).display(),
            test_dir.join(TO_GUEST_PIPE).display(),
            rootfs_path().to_str().unwrap(),
            cfg.o_direct,
        )?;

        Ok(config_file_path)
    }

    /// Instanciate a new crosvm instance using a configuration file. The first call will trigger
    /// the download of prebuilt files if necessary.
    pub fn new_with_config_file(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(
            |command, test_dir, cfg| {
                let config_file_path = TestVm::generate_json_config_file(test_dir, cfg)?;
                command.args(&["--cfg", config_file_path.to_str().unwrap()]);

                Ok(())
            },
            cfg,
        )
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
        println!("<- {:?}", trimmed);

        Ok(trimmed.to_string())
    }

    fn crosvm_command(&self, command: &str, mut args: Vec<String>) -> Result<()> {
        args.push(self.control_socket_path.to_str().unwrap().to_string());

        println!("$ crosvm {} {:?}", command, &args.join(" "));

        let mut cmd = Command::new(find_crosvm_binary());
        cmd.arg(command).args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output()?;
        // Print both the crosvm's stdout/stderr to stdout so that they'll be shown when the test
        // is failed.
        println!(
            "`crosvm {}` stdout:\n{}",
            command,
            from_utf8(&output.stdout).unwrap()
        );
        println!(
            "`crosvm {}` stderr:\n{}",
            command,
            from_utf8(&output.stderr).unwrap()
        );

        if !output.status.success() {
            Err(anyhow!("Command failed with exit code {}", output.status))
        } else {
            Ok(())
        }
    }

    pub fn stop(&self) -> Result<()> {
        self.crosvm_command("stop", vec![])
    }

    pub fn suspend(&self) -> Result<()> {
        self.crosvm_command("suspend", vec![])
    }

    pub fn resume(&self) -> Result<()> {
        self.crosvm_command("resume", vec![])
    }

    pub fn disk(&self, args: Vec<String>) -> Result<()> {
        self.crosvm_command("disk", args)
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        self.stop().unwrap();
        let output = self.process.take().unwrap().wait_with_output().unwrap();

        // Print both the crosvm's stdout/stderr to stdout so that they'll be shown when the test
        // failed.
        println!(
            "TestVm stdout:\n{}",
            std::str::from_utf8(&output.stdout).unwrap()
        );
        println!(
            "TestVm stderr:\n{}",
            std::str::from_utf8(&output.stderr).unwrap()
        );

        if !output.status.success() {
            panic!("VM exited illegally: {}", output.status);
        }
    }
}

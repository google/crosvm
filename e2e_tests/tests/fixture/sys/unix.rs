// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::O_DIRECT;
use tempfile::TempDir;

use crate::fixture::utils::find_crosvm_binary;
use crate::fixture::utils::run_with_timeout;
use crate::fixture::vm::kernel_path;
use crate::fixture::vm::rootfs_path;
use crate::fixture::vm::Config;

const FROM_GUEST_PIPE: &str = "from_guest";
const TO_GUEST_PIPE: &str = "to_guest";
const CONTROL_PIPE: &str = "control";
const VM_JSON_CONFIG_FILE: &str = "vm.json";

/// Timeout for communicating with the VM. If we do not hear back, panic so we
/// do not block the tests.
const VM_COMMUNICATION_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type SerialArgs = Path;

/// Returns the name of crosvm binary.
pub fn binary_name() -> &'static str {
    if cfg!(feature = "direct") {
        "crosvm-direct"
    } else {
        "crosvm"
    }
}

/// Safe wrapper for libc::mkfifo
pub(crate) fn mkfifo(path: &Path) -> io::Result<()> {
    let cpath = CString::new(path.to_str().unwrap()).unwrap();
    let result = unsafe { libc::mkfifo(cpath.as_ptr(), 0o777) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
pub struct TestVmSys {
    /// Maintain ownership of test_dir until the vm is destroyed.
    #[allow(dead_code)]
    pub test_dir: TempDir,
    pub from_guest_reader: Arc<Mutex<BufReader<File>>>,
    pub to_guest: Arc<Mutex<File>>,
    pub control_socket_path: PathBuf,
    pub process: Option<Child>, // Use `Option` to allow taking the ownership in `Drop::drop()`.
}

impl TestVmSys {
    // Check if the test file system is a known compatible one. Needs to support features
    // like O_DIRECT.
    pub fn check_rootfs_file(rootfs_path: &Path) {
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
        command.args(["--serial", "type=stdout"]);

        // Setup channel for communication with the delegate.
        let serial_params = format!(
            "type=file,path={},input={},num=2",
            from_guest_pipe.display(),
            to_guest_pipe.display()
        );
        command.args(["--serial", &serial_params]);
    }

    /// Configures the VM rootfs to load from the guest_under_test assets.
    fn configure_rootfs(command: &mut Command, o_direct: bool) {
        let rootfs_and_option = format!(
            "{}{},ro,root",
            rootfs_path().to_str().unwrap(),
            if o_direct { ",direct=true" } else { "" }
        );
        command
            .args(["--block", &rootfs_and_option])
            .args(["--params", "init=/bin/delegate"]);
    }

    pub fn new_generic<F>(f: F, cfg: Config) -> Result<TestVmSys>
    where
        F: FnOnce(&mut Command, &Path, &Config) -> Result<()>,
    {
        // Create two named pipes to communicate with the guest.
        let test_dir = TempDir::new()?;
        let from_guest_pipe = test_dir.path().join(FROM_GUEST_PIPE);
        let to_guest_pipe = test_dir.path().join(TO_GUEST_PIPE);
        mkfifo(&from_guest_pipe)?;
        mkfifo(&to_guest_pipe)?;

        let control_socket_path = test_dir.path().join(CONTROL_PIPE);

        let mut command = Command::new(find_crosvm_binary());
        command.args(["run"]);

        f(&mut command, test_dir.path(), &cfg)?;

        command.args(&cfg.extra_args);

        println!("$ {:?}", command);
        let mut process = Some(command.spawn()?);

        // Open pipes. Apply timeout to `from_guest` since it will block until crosvm opens the
        // other end.
        let to_guest = File::create(to_guest_pipe)?;
        let from_guest = match run_with_timeout(
            move || File::open(from_guest_pipe),
            VM_COMMUNICATION_TIMEOUT,
        ) {
            Ok(from_guest) => from_guest.with_context(|| "Cannot open from_guest pipe")?,
            Err(error) => {
                // Kill the crosvm process if we cannot connect in time.
                let mut process = process.take().unwrap();
                process.kill().unwrap();
                process.wait().unwrap();
                panic!("Cannot connect to VM: {}", error);
            }
        };

        Ok(TestVmSys {
            test_dir,
            from_guest_reader: Arc::new(Mutex::new(BufReader::new(from_guest))),
            to_guest: Arc::new(Mutex::new(to_guest)),
            control_socket_path,
            process,
        })
    }

    // Generates a config file from cfg and appends the command to use the config file.
    pub fn append_config_args(command: &mut Command, test_dir: &Path, cfg: &Config) -> Result<()> {
        TestVmSys::configure_serial_devices(
            command,
            &test_dir.join(FROM_GUEST_PIPE),
            &test_dir.join(TO_GUEST_PIPE),
        );
        command.args(["--socket", test_dir.join(CONTROL_PIPE).to_str().unwrap()]);
        TestVmSys::configure_rootfs(command, cfg.o_direct);
        // Set kernel as the last argument.
        command.arg(kernel_path());

        Ok(())
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
                  "type": "stdout"
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

    // Generates a config file from cfg and appends the command to use the config file.
    pub fn append_config_file_arg(
        command: &mut Command,
        test_dir: &Path,
        cfg: &Config,
    ) -> Result<()> {
        let config_file_path = TestVmSys::generate_json_config_file(test_dir, cfg)?;
        command.args(["--cfg", config_file_path.to_str().unwrap()]);

        Ok(())
    }

    pub fn crosvm_command(&self, command: &str, mut args: Vec<String>) -> Result<()> {
        args.push(self.control_socket_path.to_str().unwrap().to_string());

        println!("$ crosvm {} {:?}", command, &args.join(" "));

        let mut cmd = Command::new(find_crosvm_binary());
        cmd.arg(command).args(args);

        let output = cmd.output()?;
        if !output.status.success() {
            Err(anyhow!("Command failed with exit code {}", output.status))
        } else {
            Ok(())
        }
    }
}

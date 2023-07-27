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
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libc::O_DIRECT;
use tempfile::TempDir;

use crate::utils::find_crosvm_binary;
use crate::utils::run_with_status_check;
use crate::vm::local_path_from_url;
use crate::vm::Config;

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
    "crosvm"
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
        stdout_hardware_type: &str,
        from_guest_pipe: &Path,
        to_guest_pipe: &Path,
    ) {
        let stdout_serial_option = format!("type=stdout,hardware={},console", stdout_hardware_type);
        command.args(["--serial", &stdout_serial_option]);

        // Setup channel for communication with the delegate.
        let serial_params = format!(
            "type=file,path={},input={},num=2",
            from_guest_pipe.display(),
            to_guest_pipe.display()
        );
        command.args(["--serial", &serial_params]);
    }

    /// Configures the VM rootfs to load from the guest_under_test assets.
    fn configure_rootfs(command: &mut Command, o_direct: bool, path: &Path) {
        let rootfs_and_option = format!(
            "{}{},ro,root",
            path.as_os_str().to_str().unwrap(),
            if o_direct { ",direct=true" } else { "" }
        );
        command
            .args(["--block", &rootfs_and_option])
            .args(["--params", "init=/bin/delegate"]);
    }

    pub fn new_generic<F>(f: F, cfg: Config, sudo: bool) -> Result<TestVmSys>
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

        let mut command = match &cfg.wrapper_cmd {
            Some(cmd) => {
                let wrapper_splitted =
                    shlex::split(cmd).context("Failed to parse wrapper command")?;
                let mut command_tmp = if sudo {
                    let mut command = Command::new("sudo");
                    command.arg(&wrapper_splitted[0]);
                    command
                } else {
                    Command::new(&wrapper_splitted[0])
                };

                command_tmp.args(&wrapper_splitted[1..]);
                command_tmp.arg(find_crosvm_binary());
                command_tmp
            }
            None => {
                if sudo {
                    let mut command = Command::new("sudo");
                    command.arg(find_crosvm_binary());
                    command
                } else {
                    Command::new(find_crosvm_binary())
                }
            }
        };

        if let Some(log_file_name) = &cfg.log_file {
            let log_file_stdout = File::create(log_file_name)?;
            let log_file_stderr = log_file_stdout.try_clone()?;
            command.stdout(Stdio::from(log_file_stdout));
            command.stderr(Stdio::from(log_file_stderr));
        }

        command.args(["--log-level", cfg.log_level.as_str()]);
        command.args(["run"]);

        f(&mut command, test_dir.path(), &cfg)?;

        command.args(&cfg.extra_args);

        println!("$ {:?}", command);
        let mut process = command.spawn()?;

        // Open pipes. Apply timeout to `to_guest` and `from_guest` since it will block until crosvm
        // opens the other end.
        let start = Instant::now();
        let (to_guest, from_guest) = match run_with_status_check(
            move || (File::create(to_guest_pipe), File::open(from_guest_pipe)),
            Duration::from_millis(200),
            || {
                if start.elapsed() > VM_COMMUNICATION_TIMEOUT {
                    return false;
                }
                if let Some(wait_result) = process.try_wait().unwrap() {
                    println!("crosvm unexpectedly exited: {:?}", wait_result);
                    false
                } else {
                    true
                }
            },
        ) {
            Ok((to_guest, from_guest)) => (
                to_guest.context("Cannot open to_guest pipe")?,
                from_guest.context("Cannot open from_guest pipe")?,
            ),
            Err(error) => {
                // Kill the crosvm process if we cannot connect in time.
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
            process: Some(process),
        })
    }

    // Generates a config file from cfg and appends the command to use the config file.
    pub fn append_config_args(command: &mut Command, test_dir: &Path, cfg: &Config) -> Result<()> {
        TestVmSys::configure_serial_devices(
            command,
            &cfg.console_hardware,
            &test_dir.join(FROM_GUEST_PIPE),
            &test_dir.join(TO_GUEST_PIPE),
        );
        command.args(["--socket", test_dir.join(CONTROL_PIPE).to_str().unwrap()]);

        if let Some(rootfs_url) = &cfg.rootfs_url {
            TestVmSys::configure_rootfs(command, cfg.o_direct, &local_path_from_url(rootfs_url));
        };

        // Set initrd if being requested
        if let Some(initrd_url) = &cfg.initrd_url {
            command.arg("--initrd");
            command.arg(local_path_from_url(initrd_url));
        }

        // Set kernel as the last argument.
        command.arg(local_path_from_url(&cfg.kernel_url));
        Ok(())
    }

    /// Generate a JSON configuration file for `cfg` and returns its path.
    fn generate_json_config_file(test_dir: &Path, cfg: &Config) -> Result<PathBuf> {
        let config_file_path = test_dir.join(VM_JSON_CONFIG_FILE);
        let mut config_file = File::create(&config_file_path)?;

        writeln!(config_file, "{{")?;
        writeln!(
            config_file,
            r#""kernel": "{}""#,
            local_path_from_url(&cfg.kernel_url).display()
        )?;
        if let Some(initrd_url) = &cfg.initrd_url {
            writeln!(
                config_file,
                r#"",initrd": "{}""#,
                local_path_from_url(initrd_url)
                    .to_str()
                    .context("invalid initrd path")?
            )?;
        };
        writeln!(
            config_file,
            r#"
        ,"socket": "{}",
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
        ]
        "#,
            test_dir.join(CONTROL_PIPE).display(),
            test_dir.join(FROM_GUEST_PIPE).display(),
            test_dir.join(TO_GUEST_PIPE).display(),
        )?;

        if let Some(rootfs_url) = &cfg.rootfs_url {
            writeln!(
                config_file,
                r#"
                ,"block": [
                    {{
                      "path": "{}",
                      "ro": true,
                      "root": true,
                      "direct": {}
                    }}
                  ]
                  "#,
                local_path_from_url(rootfs_url)
                    .to_str()
                    .context("invalid rootfs path")?,
                cfg.o_direct,
            )?;
        };

        writeln!(config_file, "}}")?;

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

    pub fn crosvm_command(&self, command: &str, mut args: Vec<String>, sudo: bool) -> Result<()> {
        args.push(self.control_socket_path.to_str().unwrap().to_string());

        println!("$ crosvm {} {:?}", command, &args.join(" "));

        let mut cmd = if sudo {
            let mut cmd = Command::new("sudo");
            cmd.arg(find_crosvm_binary());
            cmd
        } else {
            Command::new(find_crosvm_binary())
        };

        cmd.arg(command).args(args);

        let output = cmd.output()?;
        if !output.status.success() {
            Err(anyhow!("Command failed with exit code {}", output.status))
        } else {
            Ok(())
        }
    }
}

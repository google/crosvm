// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/262270352): This file is build-only upstream as crosvm.exe cannot yet
// start a VM on windows. Enable e2e tests on windows and remove this comment.

use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base::named_pipes;
use base::PipeConnection;
use rand::Rng;

use crate::utils::find_crosvm_binary;
use crate::vm::local_path_from_url;
use crate::vm::Config;

const GUEST_EARLYCON: &str = "guest_earlycon.log";
const GUEST_CONSOLE: &str = "guest_latecon.log";
const HYPERVISOR_LOG: &str = "hypervisor.log";
const VM_JSON_CONFIG_FILE: &str = "vm.json";
// SLEEP_TIMEOUT is somewhat arbitrarily chosen by looking at a few downstream
// presubmit runs.
const SLEEP_TIMEOUT: Duration = Duration::from_millis(500);
// RETRY_COUNT is somewhat arbitrarily chosen by looking at a few downstream
// presubmit runs.
const RETRY_COUNT: u16 = 600;

pub struct SerialArgs {
    // This pipe is used to communicate to/from guest.
    from_guest_pipe: PathBuf,
    logs_dir: PathBuf,
}

/// Returns the name of crosvm binary.
pub fn binary_name() -> &'static str {
    "crosvm.exe"
}

// Generates random pipe name in device folder.
fn generate_pipe_name() -> String {
    format!(
        r"\\.\pipe\test-ipc-pipe-name.rand{}",
        rand::thread_rng().gen::<u64>(),
    )
}

// Gets custom hypervisor from `CROSVM_TEST_HYPERVISOR` environment variable or
// return `whpx` as default.
fn get_hypervisor() -> String {
    env::var("CROSVM_TEST_HYPERVISOR").unwrap_or("whpx".to_string())
}

// If the hypervisor is haxm derivative, then returns `userspace` else returns
// None.
fn get_irqchip(hypervisor: &str) -> Option<String> {
    if hypervisor == "haxm" || hypervisor == "ghaxm" {
        Some("userspace".to_string())
    } else {
        None
    }
}

// Ruturns hypervisor related args.
fn get_hypervisor_args() -> Vec<String> {
    let hypervisor = get_hypervisor();
    let mut args = if let Some(irqchip) = get_irqchip(&hypervisor) {
        vec!["--irqchip".to_owned(), irqchip]
    } else {
        vec![]
    };
    args.extend_from_slice(&["--hypervisor".to_owned(), hypervisor]);
    args
}

// Dumps logs found in `logs_dir` created by crosvm run.
fn dump_logs(logs_dir: &str) {
    let dir = Path::new(logs_dir);
    if dir.is_dir() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if !path.is_dir() {
                let data = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("Unable to read file {:?}: {:?}", &path, e));
                eprintln!("---------- {:?}", &path);
                eprintln!("{}", &data);
                eprintln!("---------- {:?}", &path);
            }
        }
    }
}

fn create_client_pipe_helper(from_guest_pipe: &str, logs_dir: &str) -> PipeConnection {
    for _ in 0..RETRY_COUNT {
        std::thread::sleep(SLEEP_TIMEOUT);
        // Open pipes. Panic if we cannot connect after a timeout.
        if let Ok(pipe) = named_pipes::create_client_pipe(
            from_guest_pipe,
            &named_pipes::FramingMode::Byte,
            &named_pipes::BlockingMode::Wait,
            false,
        ) {
            return pipe;
        }
    }

    dump_logs(logs_dir);
    panic!("Failed to open pipe from guest");
}

pub struct TestVmSys {
    pub(crate) from_guest_reader: Arc<Mutex<BufReader<PipeConnection>>>,
    pub(crate) to_guest: Arc<Mutex<PipeConnection>>,
    pub(crate) process: Option<Child>, // Use `Option` to allow taking the ownership in `Drop::drop()`.
}

impl TestVmSys {
    // Check if the test file system is a known compatible one.
    pub fn check_rootfs_file(rootfs_path: &Path) {
        // Check if the test file system is a known compatible one.
        if let Err(e) = OpenOptions::new().write(false).read(true).open(rootfs_path) {
            panic!("File open expected to work but did not: {}", e);
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
        logs_dir: &Path,
    ) {
        let earlycon_path = Path::new(logs_dir).join(GUEST_EARLYCON);
        let earlycon_str = earlycon_path.to_str().unwrap();

        command.args([
            r"--serial",
            &format!("hardware=serial,num=1,type=file,path={earlycon_str},earlycon=true"),
        ]);

        let console_path = Path::new(logs_dir).join(GUEST_CONSOLE);
        let console_str = console_path.to_str().unwrap();
        command.args([
            r"--serial",
            &format!(
                "hardware={stdout_hardware_type},num=1,type=file,path={console_str},console=true"
            ),
        ]);

        // Setup channel for communication with the delegate.
        let serial_params = format!(
            "hardware=serial,type=namedpipe,path={},num=2",
            from_guest_pipe.display(),
        );
        command.args(["--serial", &serial_params]);
    }

    /// Configures the VM rootfs to load from the guest_under_test assets.
    fn configure_rootfs(command: &mut Command, _o_direct: bool, path: &Path) {
        let rootfs_and_option = format!(
            "{},ro,root,sparse=false",
            path.as_os_str().to_str().unwrap(),
        );
        command.args(["--root", &rootfs_and_option]).args([
            "--params",
            "init=/bin/delegate noxsaves noxsave nopat nopti tsc=reliable",
        ]);
    }

    pub fn new_generic<F>(f: F, cfg: Config, _sudo: bool) -> Result<TestVmSys>
    where
        F: FnOnce(&mut Command, &SerialArgs, &Config) -> Result<()>,
    {
        let logs_dir = "emulator_logs";
        let mut logs_path = PathBuf::new();
        logs_path.push(logs_dir);
        std::fs::create_dir_all(logs_dir)?;
        // Create named pipe to communicate with the guest.
        let from_guest_path = generate_pipe_name();
        let from_guest_pipe = Path::new(&from_guest_path);

        let mut command = Command::new(find_crosvm_binary());
        command.args(["--log-level", "INFO", "run-mp"]);

        f(
            &mut command,
            &SerialArgs {
                from_guest_pipe: from_guest_pipe.to_path_buf(),
                logs_dir: logs_path,
            },
            &cfg,
        )?;

        let hypervisor_log_path = Path::new(logs_dir).join(HYPERVISOR_LOG);
        let hypervisor_log_str = hypervisor_log_path.to_str().unwrap();
        command.args([
            "--logs-directory",
            logs_dir,
            "--kernel-log-file",
            hypervisor_log_str,
        ]);
        command.args(&get_hypervisor_args());
        command.args(cfg.extra_args);

        println!("Running command: {:?}", command);

        let process = Some(command.spawn().unwrap());

        let to_guest = create_client_pipe_helper(&from_guest_path, logs_dir);
        let from_guest_reader = BufReader::new(to_guest.try_clone().unwrap());

        Ok(TestVmSys {
            from_guest_reader: Arc::new(Mutex::new(from_guest_reader)),
            to_guest: Arc::new(Mutex::new(to_guest)),
            process,
        })
    }

    // Generates a config file from cfg and appends the command to use the config file.
    pub fn append_config_args(
        command: &mut Command,
        serial_args: &SerialArgs,
        cfg: &Config,
    ) -> Result<()> {
        TestVmSys::configure_serial_devices(
            command,
            &cfg.console_hardware,
            &serial_args.from_guest_pipe,
            &serial_args.logs_dir,
        );
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
    fn generate_json_config_file(
        from_guest_pipe: &Path,
        logs_path: &Path,
        cfg: &Config,
    ) -> Result<PathBuf> {
        let config_file_path = logs_path.join(VM_JSON_CONFIG_FILE);
        let mut config_file = File::create(&config_file_path)?;

        writeln!(config_file, "{{")?;

        writeln!(
            config_file,
            r#"
              "params": [ "init=/bin/delegate noxsaves noxsave nopat nopti tsc=reliable" ],
              "serial": [
                {{
                    "type": "file",
                    "hardware": "serial",
                    "num": "1",
                    "path": "{}",
                    "earlycon": "true"
                }},
                {{
                    "type": "file",
                    "path": "{}",
                    "hardware": "serial",
                    "num": "1",
                    "console": "true"
                   }},
                {{
                    "hardware": "serial",
                    "num": "2",
                    "type": "namedpipe",
                    "path": "{}",
                }},
              ]
            }}
            "#,
            logs_path.join(GUEST_EARLYCON).display(),
            logs_path.join(GUEST_CONSOLE).display(),
            from_guest_pipe.display()
        )?;

        if let Some(rootfs_url) = &cfg.rootfs_url {
            writeln!(
                config_file,
                r#"
                ,"root": [
                {{
                  "path": "{}",
                  "ro": true,
                  "root": true,
                  "sparse": false
                }}
              ]
                  "#,
                local_path_from_url(rootfs_url)
                    .to_str()
                    .context("invalid rootfs path")?,
            )?;
        };
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
        ,"logs-directory": "{}",
        "kernel-log-file": "{},
        "hypervisor": "{}"
        {},
        {}"#,
            logs_path.display(),
            logs_path.join(HYPERVISOR_LOG).display(),
            get_hypervisor(),
            local_path_from_url(&cfg.kernel_url).display(),
            &get_irqchip(&get_hypervisor()).map_or("".to_owned(), |irqchip| format!(
                r#","irqchip": "{}""#,
                irqchip
            ))
        )?;

        writeln!(config_file, "}}")?;

        Ok(config_file_path)
    }

    // Generates a config file from cfg and appends the command to use the config file.
    pub fn append_config_file_arg(
        command: &mut Command,
        serial_args: &SerialArgs,
        cfg: &Config,
    ) -> Result<()> {
        let config_file_path = TestVmSys::generate_json_config_file(
            &serial_args.from_guest_pipe,
            &serial_args.logs_dir,
            cfg,
        )?;
        command.args(["--cfg", config_file_path.to_str().unwrap()]);

        Ok(())
    }

    pub fn crosvm_command(
        &mut self,
        _command: &str,
        mut _args: Vec<String>,
        _sudo: bool,
    ) -> Result<Vec<u8>> {
        unimplemented!()
    }
}

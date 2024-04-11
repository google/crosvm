// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::syslog;
use base::test_utils::check_can_sudo;
use crc32fast::hash;
use delegate::wire_format::DelegateMessage;
use delegate::wire_format::ExitStatus;
use delegate::wire_format::GuestToHostMessage;
use delegate::wire_format::HostToGuestMessage;
use delegate::wire_format::ProgramExit;
use log::info;
use log::Level;
use prebuilts::download_file;
use readclock::ClockValues;
use url::Url;

use crate::sys::SerialArgs;
use crate::sys::TestVmSys;
use crate::utils::run_with_timeout;

const PREBUILT_URL: &str = "https://storage.googleapis.com/crosvm/integration_tests";

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "arm")]
const ARCH: &str = "arm";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";
#[cfg(target_arch = "riscv64")]
const ARCH: &str = "riscv64";

/// Timeout when waiting for pipes that are expected to be ready.
const COMMUNICATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for the VM to boot and the delegate to report that it's ready.
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);

/// Default timeout when waiting for guest commands to execute
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

fn prebuilt_version() -> &'static str {
    include_str!("../../guest_under_test/PREBUILT_VERSION").trim()
}

fn kernel_prebuilt_url_string() -> Url {
    Url::parse(&format!(
        "{}/guest-bzimage-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    ))
    .unwrap()
}

fn rootfs_prebuilt_url_string() -> Url {
    Url::parse(&format!(
        "{}/guest-rootfs-{}-{}",
        PREBUILT_URL,
        ARCH,
        prebuilt_version()
    ))
    .unwrap()
}

pub(super) fn local_path_from_url(url: &Url) -> PathBuf {
    if url.scheme() == "file" {
        return url.to_file_path().unwrap();
    }
    if url.scheme() != "http" && url.scheme() != "https" {
        panic!("Only file, http, https URLs are supported for artifacts")
    }
    env::current_exe().unwrap().parent().unwrap().join(format!(
        "e2e_prebuilt-{:x}-{:x}",
        hash(url.as_str().as_bytes()),
        hash(url.path().as_bytes())
    ))
}

/// Represents a command running in the guest. See `TestVm::exec_in_guest_async()`
#[must_use]
pub struct GuestProcess {
    command: String,
    timeout: Duration,
}

impl GuestProcess {
    pub fn with_timeout(self, duration: Duration) -> Self {
        Self {
            timeout: duration,
            ..self
        }
    }

    /// Waits for the process to finish execution and return ExitStatus.
    /// Will fail on a non-zero exit code.
    pub fn wait_ok(self, vm: &mut TestVm) -> Result<ProgramExit> {
        let command = self.command.clone();
        let result = self.wait_result(vm)?;

        match &result.exit_status {
            ExitStatus::Code(0) => Ok(result),
            ExitStatus::Code(code) => {
                bail!("Command `{}` terminated with exit code {}", command, code)
            }
            ExitStatus::Signal(code) => bail!("Command `{}` stopped with signal {}", command, code),
            ExitStatus::None => bail!("Command `{}` stopped for unknown reason", command),
        }
    }

    /// Same as `wait_ok` but will return a ExitStatus instead of failing on a non-zero exit code,
    /// will only fail when cannot receive output from guest.
    pub fn wait_result(self, vm: &mut TestVm) -> Result<ProgramExit> {
        let message = vm.read_message_from_guest(self.timeout).with_context(|| {
            format!(
                "Command `{}`: Failed to read response from guest",
                self.command
            )
        })?;
        // VM is ready when receiving any message (as for current protocol)
        match message {
            GuestToHostMessage::ProgramExit(exit_info) => Ok(exit_info),
            _ => bail!("Receive other message when anticipating ProgramExit"),
        }
    }
}

/// Configuration to start `TestVm`.
pub struct Config {
    /// Extra arguments for the `run` subcommand.
    pub(super) extra_args: Vec<String>,

    /// Use `O_DIRECT` for the rootfs.
    pub(super) o_direct: bool,

    /// Log level of `TestVm`
    pub(super) log_level: Level,

    /// File to save crosvm log to
    pub(super) log_file: Option<String>,

    /// Wrapper command line for executing `TestVM`
    pub(super) wrapper_cmd: Option<String>,

    /// Url to kernel image
    pub(super) kernel_url: Url,

    /// Url to initrd image
    pub(super) initrd_url: Option<Url>,

    /// Url to rootfs image
    pub(super) rootfs_url: Option<Url>,

    /// If rootfs image is writable
    pub(super) rootfs_rw: bool,

    /// If rootfs image is zstd compressed
    pub(super) rootfs_compressed: bool,

    /// Console hardware type
    pub(super) console_hardware: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: Level::Info,
            extra_args: Default::default(),
            o_direct: Default::default(),
            log_file: None,
            wrapper_cmd: None,
            kernel_url: kernel_prebuilt_url_string(),
            initrd_url: None,
            rootfs_url: Some(rootfs_prebuilt_url_string()),
            rootfs_rw: false,
            rootfs_compressed: false,
            console_hardware: "virtio-console".to_owned(),
        }
    }
}

impl Config {
    /// Creates a new `run` command with `extra_args`.
    pub fn new() -> Self {
        Self::from_env()
    }

    /// Uses extra arguments for `crosvm run`.
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

    pub fn from_env() -> Self {
        let mut cfg: Config = Default::default();
        if let Ok(wrapper_cmd) = env::var("CROSVM_CARGO_TEST_E2E_WRAPPER_CMD") {
            cfg.wrapper_cmd = Some(wrapper_cmd);
        }
        if let Ok(log_file) = env::var("CROSVM_CARGO_TEST_LOG_FILE") {
            cfg.log_file = Some(log_file);
        }
        if env::var("CROSVM_CARGO_TEST_LOG_LEVEL_DEBUG").is_ok() {
            cfg.log_level = Level::Debug;
        }
        if let Ok(kernel_url) = env::var("CROSVM_CARGO_TEST_KERNEL_IMAGE") {
            info!("Using overrided kernel from env CROSVM_CARGO_TEST_KERNEL_IMAGE={kernel_url}");
            cfg.kernel_url = Url::from_file_path(kernel_url).unwrap();
        }
        if let Ok(initrd_url) = env::var("CROSVM_CARGO_TEST_INITRD_IMAGE") {
            info!("Using overrided kernel from env CROSVM_CARGO_TEST_INITRD_IMAGE={initrd_url}");
            cfg.initrd_url = Some(Url::from_file_path(initrd_url).unwrap());
        }
        if let Ok(rootfs_url) = env::var("CROSVM_CARGO_TEST_ROOTFS_IMAGE") {
            info!("Using overrided kernel from env CROSVM_CARGO_TEST_ROOTFS_IMAGE={rootfs_url}");
            cfg.rootfs_url = Some(Url::from_file_path(rootfs_url).unwrap());
        }
        cfg
    }

    pub fn with_kernel(mut self, url: &str) -> Self {
        self.kernel_url = Url::parse(url).unwrap();
        self
    }

    pub fn with_initrd(mut self, url: &str) -> Self {
        self.initrd_url = Some(Url::parse(url).unwrap());
        self
    }

    pub fn with_rootfs(mut self, url: &str) -> Self {
        self.rootfs_url = Some(Url::parse(url).unwrap());
        self
    }

    pub fn rootfs_is_rw(mut self) -> Self {
        self.rootfs_rw = true;
        self
    }

    pub fn rootfs_is_compressed(mut self) -> Self {
        self.rootfs_compressed = true;
        self
    }

    pub fn with_stdout_hardware(mut self, hw_type: &str) -> Self {
        self.console_hardware = hw_type.to_owned();
        self
    }

    pub fn with_vhost_user(mut self, device_type: &str, socket_path: &Path) -> Self {
        self.extra_args.push("--vhost-user".to_string());
        self.extra_args.push(format!(
            "{},socket={}",
            device_type,
            socket_path.to_str().unwrap()
        ));
        self
    }
}

static PREP_ONCE: Once = Once::new();

/// Test fixture to spin up a VM running a guest that can be communicated with.
///
/// After creation, commands can be sent via exec_in_guest. The VM is stopped
/// when this instance is dropped.
pub struct TestVm {
    // Platform-dependent bits
    sys: TestVmSys,
    // The guest is ready to receive a command.
    ready: bool,
    // True if commands should be ran with `sudo`.
    sudo: bool,
}

impl TestVm {
    /// Downloads prebuilts if needed.
    fn initialize_once() {
        if let Err(e) = syslog::init() {
            panic!("failed to initiailize syslog: {}", e);
        }

        // It's possible the prebuilts downloaded by crosvm-9999.ebuild differ
        // from the version that crosvm was compiled for.
        info!("Prebuilt version to be used: {}", prebuilt_version());
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
    }

    fn initiailize_artifacts(cfg: &Config) {
        let kernel_path = local_path_from_url(&cfg.kernel_url);
        if !kernel_path.exists() && cfg.kernel_url.scheme() != "file" {
            download_file(cfg.kernel_url.as_str(), &kernel_path).unwrap();
        }
        assert!(kernel_path.exists(), "{:?} does not exist", kernel_path);

        if let Some(initrd_url) = &cfg.initrd_url {
            let initrd_path = local_path_from_url(initrd_url);
            if !initrd_path.exists() && initrd_url.scheme() != "file" {
                download_file(initrd_url.as_str(), &initrd_path).unwrap();
            }
            assert!(initrd_path.exists(), "{:?} does not exist", initrd_path);
        }

        if let Some(rootfs_url) = &cfg.rootfs_url {
            let rootfs_download_path = local_path_from_url(rootfs_url);
            if !rootfs_download_path.exists() && rootfs_url.scheme() != "file" {
                download_file(rootfs_url.as_str(), &rootfs_download_path).unwrap();
            }
            assert!(
                rootfs_download_path.exists(),
                "{:?} does not exist",
                rootfs_download_path
            );

            if cfg.rootfs_compressed {
                let rootfs_raw_path = rootfs_download_path.with_extension("raw");
                Command::new("zstd")
                    .arg("-d")
                    .arg(&rootfs_download_path)
                    .arg("-o")
                    .arg(&rootfs_raw_path)
                    .arg("-f")
                    .output()
                    .expect("Failed to decompress rootfs");
                TestVmSys::check_rootfs_file(&rootfs_raw_path);
            } else {
                TestVmSys::check_rootfs_file(&rootfs_download_path);
            }
        }
    }

    /// Instanciate a new crosvm instance. The first call will trigger the download of prebuilt
    /// files if necessary.
    ///
    /// This generic method takes a `FnOnce` argument which is in charge of completing the `Command`
    /// with all the relevant options needed to boot the VM.
    pub fn new_generic<F>(f: F, cfg: Config, sudo: bool) -> Result<TestVm>
    where
        F: FnOnce(&mut Command, &SerialArgs, &Config) -> Result<()>,
    {
        PREP_ONCE.call_once(TestVm::initialize_once);

        TestVm::initiailize_artifacts(&cfg);

        let mut vm = TestVm {
            sys: TestVmSys::new_generic(f, cfg, sudo).with_context(|| "Could not start crosvm")?,
            ready: false,
            sudo,
        };
        vm.wait_for_guest_ready(BOOT_TIMEOUT)
            .with_context(|| "Guest did not become ready after boot")?;
        Ok(vm)
    }

    pub fn new_generic_restore<F>(f: F, cfg: Config, sudo: bool) -> Result<TestVm>
    where
        F: FnOnce(&mut Command, &SerialArgs, &Config) -> Result<()>,
    {
        PREP_ONCE.call_once(TestVm::initialize_once);
        let mut vm = TestVm {
            sys: TestVmSys::new_generic(f, cfg, sudo).with_context(|| "Could not start crosvm")?,
            ready: false,
            sudo,
        };
        vm.ready = true;
        // TODO(b/280607404): A cold restored VM cannot respond to cmds from `exec_in_guest_async`.
        Ok(vm)
    }

    pub fn new(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(TestVmSys::append_config_args, cfg, false)
    }

    /// Create `TestVm` from a snapshot, using `--restore` but NOT `--suspended`.
    pub fn new_restore(cfg: Config) -> Result<TestVm> {
        let mut vm = TestVm::new_generic_restore(TestVmSys::append_config_args, cfg, false)?;
        // Send a resume request to wait for the restore to finish.
        // We don't want to return from this function until the restore is complete, otherwise it
        // will be difficult to differentiate between a slow restore and a slow response from the
        // guest.
        let vm = run_with_timeout(
            move || {
                vm.resume_full().expect("failed to resume after VM restore");
                vm
            },
            Duration::from_secs(60),
        )
        .expect("VM restore timeout");

        Ok(vm)
    }

    /// Create `TestVm` from a snapshot, using `--restore` AND `--suspended`.
    pub fn new_restore_suspended(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic_restore(TestVmSys::append_config_args, cfg, false)
    }

    pub fn new_sudo(cfg: Config) -> Result<TestVm> {
        check_can_sudo();

        TestVm::new_generic(TestVmSys::append_config_args, cfg, true)
    }

    /// Instanciate a new crosvm instance using a configuration file. The first call will trigger
    /// the download of prebuilt files if necessary.
    pub fn new_with_config_file(cfg: Config) -> Result<TestVm> {
        TestVm::new_generic(TestVmSys::append_config_file_arg, cfg, false)
    }

    /// Executes the provided command in the guest.
    /// Returns command output as Ok(ProgramExit), or an Error if the program did not exit with 0.
    pub fn exec_in_guest(&mut self, command: &str) -> Result<ProgramExit> {
        self.exec_in_guest_async(command)?.wait_ok(self)
    }

    /// Same as `exec_in_guest` but will return Ok(ProgramExit) instead of failing on a
    /// non-zero exit code.
    pub fn exec_in_guest_unchecked(&mut self, command: &str) -> Result<ProgramExit> {
        self.exec_in_guest_async(command)?.wait_result(self)
    }

    /// Executes the provided command in the guest asynchronously.
    /// The command will be run in the guest, but output will not be read until
    /// GuestProcess::wait_ok() or GuestProcess::wait_result() is called.
    pub fn exec_in_guest_async(&mut self, command: &str) -> Result<GuestProcess> {
        assert!(self.ready);
        self.ready = false;

        // Send command to guest
        self.write_message_to_guest(
            &HostToGuestMessage::RunCommand {
                command: command.to_owned(),
            },
            COMMUNICATION_TIMEOUT,
        )
        .with_context(|| format!("Command `{}`: Failed to write to guest pipe", command))?;

        Ok(GuestProcess {
            command: command.to_owned(),
            timeout: DEFAULT_COMMAND_TIMEOUT,
        })
    }

    // Waits for the guest to be ready to receive commands
    fn wait_for_guest_ready(&mut self, timeout: Duration) -> Result<()> {
        assert!(!self.ready);
        let message: GuestToHostMessage = self.read_message_from_guest(timeout)?;
        match message {
            GuestToHostMessage::Ready => {
                self.ready = true;
                Ok(())
            }
            _ => Err(anyhow!("Recevied unexpected data from delegate")),
        }
    }

    /// Reads one line via the `from_guest` pipe from the guest delegate.
    fn read_message_from_guest(&mut self, timeout: Duration) -> Result<GuestToHostMessage> {
        let reader = self.sys.from_guest_reader.clone();

        let result = run_with_timeout(
            move || loop {
                let message = { reader.lock().unwrap().next() };

                if let Some(message_result) = message {
                    if let Ok(msg) = message_result {
                        match msg {
                            DelegateMessage::GuestToHost(guest_to_host) => {
                                return Ok(guest_to_host);
                            }
                            // Guest will send an echo of the message sent from host, ignore it
                            DelegateMessage::HostToGuest(_) => {
                                continue;
                            }
                        }
                    } else {
                        bail!(format!(
                            "Failed to receive message from guest: {:?}",
                            message_result.unwrap_err()
                        ))
                    };
                };
            },
            timeout,
        );
        match result {
            Ok(x) => {
                self.ready = true;
                x
            }
            Err(x) => Err(x),
        }
    }

    /// Send one line via the `to_guest` pipe to the guest delegate.
    fn write_message_to_guest(
        &mut self,
        data: &HostToGuestMessage,
        timeout: Duration,
    ) -> Result<()> {
        let writer = self.sys.to_guest.clone();
        let data_str = serde_json::to_string_pretty(&DelegateMessage::HostToGuest(data.clone()))?;
        run_with_timeout(
            move || -> Result<()> {
                println!("-> {}", &data_str);
                {
                    writeln!(writer.lock().unwrap(), "{}", &data_str)?;
                }
                Ok(())
            },
            timeout,
        )?
    }

    /// Hotplug a tap device.
    pub fn hotplug_tap(&mut self, tap_name: &str) -> Result<()> {
        self.sys
            .crosvm_command(
                "virtio-net",
                vec!["add".to_owned(), tap_name.to_owned()],
                self.sudo,
            )
            .map(|_| ())
    }

    /// Remove hotplugged device on bus.
    pub fn remove_pci_device(&mut self, bus_num: u8) -> Result<()> {
        self.sys
            .crosvm_command(
                "virtio-net",
                vec!["remove".to_owned(), bus_num.to_string()],
                self.sudo,
            )
            .map(|_| ())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.sys
            .crosvm_command("stop", vec![], self.sudo)
            .map(|_| ())
    }

    pub fn suspend(&mut self) -> Result<()> {
        self.sys
            .crosvm_command("suspend", vec![], self.sudo)
            .map(|_| ())
    }

    pub fn suspend_full(&mut self) -> Result<()> {
        self.sys
            .crosvm_command("suspend", vec!["--full".to_string()], self.sudo)
            .map(|_| ())
    }

    pub fn resume(&mut self) -> Result<()> {
        self.sys
            .crosvm_command("resume", vec![], self.sudo)
            .map(|_| ())
    }

    pub fn resume_full(&mut self) -> Result<()> {
        self.sys
            .crosvm_command("resume", vec!["--full".to_string()], self.sudo)
            .map(|_| ())
    }

    pub fn disk(&mut self, args: Vec<String>) -> Result<()> {
        self.sys.crosvm_command("disk", args, self.sudo).map(|_| ())
    }

    pub fn snapshot(&mut self, filename: &std::path::Path) -> Result<()> {
        self.sys
            .crosvm_command(
                "snapshot",
                vec!["take".to_string(), String::from(filename.to_str().unwrap())],
                self.sudo,
            )
            .map(|_| ())
    }

    // No argument is passed in restore as we will always restore snapshot.bkp for testing.
    pub fn restore(&mut self, filename: &std::path::Path) -> Result<()> {
        self.sys
            .crosvm_command(
                "snapshot",
                vec![
                    "restore".to_string(),
                    String::from(filename.to_str().unwrap()),
                ],
                self.sudo,
            )
            .map(|_| ())
    }

    pub fn swap_command(&mut self, command: &str) -> Result<Vec<u8>> {
        self.sys
            .crosvm_command("swap", vec![command.to_string()], self.sudo)
    }

    pub fn guest_clock_values(&mut self) -> Result<ClockValues> {
        let output = self
            .exec_in_guest("readclock")
            .context("Failed to execute readclock binary")?;
        serde_json::from_str(&output.stdout).context("Failed to parse result")
    }
}

impl Drop for TestVm {
    fn drop(&mut self) {
        self.stop().unwrap();
        let status = self.sys.process.take().unwrap().wait().unwrap();
        if !status.success() {
            panic!("VM exited illegally: {}", status);
        }
    }
}

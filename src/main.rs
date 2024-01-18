// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine
//!
//! ## Feature flags
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]

#[cfg(any(feature = "composite-disk", feature = "qcow"))]
use std::fs::OpenOptions;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use argh::FromArgs;
use base::debug;
use base::error;
use base::info;
use base::syslog;
use base::syslog::LogArgs;
use base::syslog::LogConfig;
use cmdline::RunCommand;
mod crosvm;
use crosvm::cmdline;
#[cfg(feature = "plugin")]
use crosvm::config::executable_is_plugin;
use crosvm::config::Config;
use devices::virtio::vhost::user::device::run_block_device;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::run_gpu_device;
#[cfg(feature = "net")]
use devices::virtio::vhost::user::device::run_net_device;
#[cfg(feature = "audio")]
use devices::virtio::vhost::user::device::run_snd_device;
#[cfg(feature = "composite-disk")]
use disk::create_composite_disk;
#[cfg(feature = "composite-disk")]
use disk::create_disk_file;
#[cfg(feature = "composite-disk")]
use disk::create_zero_filler;
#[cfg(feature = "composite-disk")]
use disk::ImagePartitionType;
#[cfg(feature = "composite-disk")]
use disk::PartitionInfo;
#[cfg(feature = "qcow")]
use disk::QcowFile;
mod sys;
use crosvm::cmdline::Command;
use crosvm::cmdline::CrossPlatformCommands;
use crosvm::cmdline::CrossPlatformDevicesCommands;
#[cfg(windows)]
use sys::windows::setup_metrics_reporting;
#[cfg(feature = "gpu")]
use vm_control::client::do_gpu_display_add;
#[cfg(feature = "gpu")]
use vm_control::client::do_gpu_display_list;
#[cfg(feature = "gpu")]
use vm_control::client::do_gpu_display_remove;
#[cfg(feature = "gpu")]
use vm_control::client::do_gpu_set_display_mouse_mode;
use vm_control::client::do_modify_battery;
#[cfg(feature = "pci-hotplug")]
use vm_control::client::do_net_add;
#[cfg(feature = "pci-hotplug")]
use vm_control::client::do_net_remove;
use vm_control::client::do_security_key_attach;
use vm_control::client::do_swap_status;
use vm_control::client::do_usb_attach;
use vm_control::client::do_usb_detach;
use vm_control::client::do_usb_list;
#[cfg(feature = "balloon")]
use vm_control::client::handle_request;
use vm_control::client::vms_request;
#[cfg(feature = "gpu")]
use vm_control::client::ModifyGpuResult;
use vm_control::client::ModifyUsbResult;
#[cfg(feature = "balloon")]
use vm_control::BalloonControlCommand;
use vm_control::DiskControlCommand;
use vm_control::HotPlugDeviceInfo;
use vm_control::HotPlugDeviceType;
use vm_control::RestoreCommand;
use vm_control::SnapshotCommand;
use vm_control::SwapCommand;
use vm_control::UsbControlResult;
use vm_control::VmRequest;
#[cfg(feature = "balloon")]
use vm_control::VmResponse;

use crate::sys::error_to_exit_code;
use crate::sys::init_log;

#[cfg(feature = "scudo")]
#[global_allocator]
static ALLOCATOR: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Exit code from crosvm,
enum CommandStatus {
    /// Exit with success. Also used to mean VM stopped successfully.
    SuccessOrVmStop = 0,
    /// VM requested reset.
    VmReset = 32,
    /// VM crashed.
    VmCrash = 33,
    /// VM exit due to kernel panic in guest.
    GuestPanic = 34,
    /// Invalid argument was given to crosvm.
    InvalidArgs = 35,
    /// VM exit due to vcpu stall detection.
    WatchdogReset = 36,
}

impl CommandStatus {
    fn message(&self) -> &'static str {
        match self {
            Self::SuccessOrVmStop => "exiting with success",
            Self::VmReset => "exiting with reset",
            Self::VmCrash => "exiting with crash",
            Self::GuestPanic => "exiting with guest panic",
            Self::InvalidArgs => "invalid argument",
            Self::WatchdogReset => "exiting with watchdog reset",
        }
    }
}

impl From<sys::ExitState> for CommandStatus {
    fn from(result: sys::ExitState) -> CommandStatus {
        match result {
            sys::ExitState::Stop => CommandStatus::SuccessOrVmStop,
            sys::ExitState::Reset => CommandStatus::VmReset,
            sys::ExitState::Crash => CommandStatus::VmCrash,
            sys::ExitState::GuestPanic => CommandStatus::GuestPanic,
            sys::ExitState::WatchdogReset => CommandStatus::WatchdogReset,
        }
    }
}

fn run_vm(cmd: RunCommand, log_config: LogConfig) -> Result<CommandStatus> {
    let cfg = match TryInto::<Config>::try_into(cmd) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{}", e);
            return Err(anyhow!("{}", e));
        }
    };

    #[cfg(feature = "plugin")]
    if executable_is_plugin(&cfg.executable_path) {
        let res = match crosvm::plugin::run_config(cfg) {
            Ok(_) => {
                info!("crosvm and plugin have exited normally");
                Ok(CommandStatus::SuccessOrVmStop)
            }
            Err(e) => {
                eprintln!("{:#}", e);
                Err(e)
            }
        };
        return res;
    }

    #[cfg(feature = "crash-report")]
    crosvm::sys::setup_emulator_crash_reporting(&cfg)?;

    #[cfg(windows)]
    setup_metrics_reporting()?;

    init_log(log_config, &cfg)?;
    cros_tracing::init();
    let exit_state = crate::sys::run_config(cfg)?;
    Ok(CommandStatus::from(exit_state))
}

fn stop_vms(cmd: cmdline::StopCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Exit, cmd.socket_path)
}

fn suspend_vms(cmd: cmdline::SuspendCommand) -> std::result::Result<(), ()> {
    if cmd.full {
        vms_request(&VmRequest::SuspendVm, cmd.socket_path)
    } else {
        vms_request(&VmRequest::SuspendVcpus, cmd.socket_path)
    }
}

fn swap_vms(cmd: cmdline::SwapCommand) -> std::result::Result<(), ()> {
    use cmdline::SwapSubcommands::*;
    let (req, path) = match &cmd.nested {
        Enable(params) => (VmRequest::Swap(SwapCommand::Enable), &params.socket_path),
        Trim(params) => (VmRequest::Swap(SwapCommand::Trim), &params.socket_path),
        SwapOut(params) => (VmRequest::Swap(SwapCommand::SwapOut), &params.socket_path),
        Disable(params) => (
            VmRequest::Swap(SwapCommand::Disable {
                slow_file_cleanup: params.slow_file_cleanup,
            }),
            &params.socket_path,
        ),
        Status(params) => (VmRequest::Swap(SwapCommand::Status), &params.socket_path),
    };
    if let VmRequest::Swap(SwapCommand::Status) = req {
        do_swap_status(path)
    } else {
        vms_request(&req, path)
    }
}

fn resume_vms(cmd: cmdline::ResumeCommand) -> std::result::Result<(), ()> {
    if cmd.full {
        vms_request(&VmRequest::ResumeVm, cmd.socket_path)
    } else {
        vms_request(&VmRequest::ResumeVcpus, cmd.socket_path)
    }
}

fn powerbtn_vms(cmd: cmdline::PowerbtnCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Powerbtn, cmd.socket_path)
}

fn sleepbtn_vms(cmd: cmdline::SleepCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Sleepbtn, cmd.socket_path)
}

fn inject_gpe(cmd: cmdline::GpeCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Gpe(cmd.gpe), cmd.socket_path)
}

#[cfg(feature = "balloon")]
fn balloon_vms(cmd: cmdline::BalloonCommand) -> std::result::Result<(), ()> {
    let command = BalloonControlCommand::Adjust {
        num_bytes: cmd.num_bytes,
        wait_for_success: cmd.wait,
    };
    vms_request(&VmRequest::BalloonCommand(command), cmd.socket_path)
}

#[cfg(feature = "balloon")]
fn balloon_stats(cmd: cmdline::BalloonStatsCommand) -> std::result::Result<(), ()> {
    let command = BalloonControlCommand::Stats {};
    let request = &VmRequest::BalloonCommand(command);
    let response = handle_request(request, cmd.socket_path)?;
    match serde_json::to_string_pretty(&response) {
        Ok(response_json) => println!("{}", response_json),
        Err(e) => {
            error!("Failed to serialize into JSON: {}", e);
            return Err(());
        }
    }
    match response {
        VmResponse::BalloonStats { .. } => Ok(()),
        _ => Err(()),
    }
}

#[cfg(feature = "balloon")]
fn balloon_ws(cmd: cmdline::BalloonWsCommand) -> std::result::Result<(), ()> {
    let command = BalloonControlCommand::WorkingSet {};
    let request = &VmRequest::BalloonCommand(command);
    let response = handle_request(request, cmd.socket_path)?;
    match serde_json::to_string_pretty(&response) {
        Ok(response_json) => println!("{response_json}"),
        Err(e) => {
            error!("Failed to serialize into JSON: {e}");
            return Err(());
        }
    }
    match response {
        VmResponse::BalloonWS { .. } => Ok(()),
        _ => Err(()),
    }
}

fn modify_battery(cmd: cmdline::BatteryCommand) -> std::result::Result<(), ()> {
    do_modify_battery(
        cmd.socket_path,
        &cmd.battery_type,
        &cmd.property,
        &cmd.target,
    )
}

fn modify_vfio(cmd: cmdline::VfioCrosvmCommand) -> std::result::Result<(), ()> {
    let (request, socket_path, vfio_path) = match cmd.command {
        cmdline::VfioSubCommand::Add(c) => {
            let request = VmRequest::HotPlugVfioCommand {
                device: HotPlugDeviceInfo {
                    device_type: HotPlugDeviceType::EndPoint,
                    path: c.vfio_path.clone(),
                    hp_interrupt: true,
                },
                add: true,
            };
            (request, c.socket_path, c.vfio_path)
        }
        cmdline::VfioSubCommand::Remove(c) => {
            let request = VmRequest::HotPlugVfioCommand {
                device: HotPlugDeviceInfo {
                    device_type: HotPlugDeviceType::EndPoint,
                    path: c.vfio_path.clone(),
                    hp_interrupt: false,
                },
                add: false,
            };
            (request, c.socket_path, c.vfio_path)
        }
    };
    if !vfio_path.exists() || !vfio_path.is_dir() {
        error!("Invalid host sysfs path: {:?}", vfio_path);
        return Err(());
    }

    vms_request(&request, socket_path)?;
    Ok(())
}

#[cfg(feature = "pci-hotplug")]
fn modify_virtio_net(cmd: cmdline::VirtioNetCommand) -> std::result::Result<(), ()> {
    match cmd.command {
        cmdline::VirtioNetSubCommand::AddTap(c) => {
            let bus_num = do_net_add(&c.tap_name, c.socket_path).map_err(|e| {
                error!("{}", &e);
            })?;
            info!("Tap device {} plugged to PCI bus {}", &c.tap_name, bus_num);
        }
        cmdline::VirtioNetSubCommand::RemoveTap(c) => {
            do_net_remove(c.bus, &c.socket_path).map_err(|e| {
                error!("Tap device remove failed: {:?}", &e);
            })?;
            info!("Tap device removed from PCI bus {}", &c.bus);
        }
    };

    Ok(())
}

#[cfg(feature = "composite-disk")]
fn parse_composite_partition_arg(
    partition_arg: &str,
) -> std::result::Result<(String, String, bool), ()> {
    let mut partition_fields = partition_arg.split(":");

    let label = partition_fields.next();
    let path = partition_fields.next();
    let opt = partition_fields.next();

    if let (Some(label), Some(path)) = (label, path) {
        // By default, composite disk is read-only
        let writable = match opt {
            None => false,
            Some(opt) => opt.contains("writable"),
        };
        Ok((label.to_owned(), path.to_owned(), writable))
    } else {
        error!(
            "Must specify label and path for partition '{}', like LABEL:PARTITION",
            partition_arg
        );
        Err(())
    }
}

#[cfg(feature = "composite-disk")]
fn create_composite(cmd: cmdline::CreateCompositeCommand) -> std::result::Result<(), ()> {
    use std::fs::File;
    use std::path::PathBuf;

    let composite_image_path = &cmd.path;
    let zero_filler_path = format!("{}.filler", composite_image_path);
    let header_path = format!("{}.header", composite_image_path);
    let footer_path = format!("{}.footer", composite_image_path);

    let mut composite_image_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(composite_image_path)
        .map_err(|e| {
            error!(
                "Failed opening composite disk image file at '{}': {}",
                composite_image_path, e
            );
        })?;
    create_zero_filler(&zero_filler_path).map_err(|e| {
        error!(
            "Failed to create zero filler file at '{}': {}",
            &zero_filler_path, e
        );
    })?;
    let mut header_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&header_path)
        .map_err(|e| {
            error!(
                "Failed opening header image file at '{}': {}",
                header_path, e
            );
        })?;
    let mut footer_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&footer_path)
        .map_err(|e| {
            error!(
                "Failed opening footer image file at '{}': {}",
                footer_path, e
            );
        })?;

    let partitions = cmd
        .partitions
        .into_iter()
        .map(|partition_arg| {
            let (label, path, writable) = parse_composite_partition_arg(&partition_arg)?;

            let partition_file =
                File::open(&path).map_err(|e| error!("Failed to open partition image: {}", e))?;

            // Sparseness for composite disks is not user provided on Linux
            // (e.g. via an option), and it has no runtime effect.
            let size = create_disk_file(
                partition_file,
                /* is_sparse_file= */ true,
                disk::MAX_NESTING_DEPTH,
                Path::new(&path),
            )
            .map_err(|e| error!("Failed to create DiskFile instance: {}", e))?
            .get_len()
            .map_err(|e| error!("Failed to get length of partition image: {}", e))?;

            Ok(PartitionInfo {
                label,
                path: Path::new(&path).to_owned(),
                partition_type: ImagePartitionType::LinuxFilesystem,
                writable,
                size,
            })
        })
        .collect::<Result<Vec<PartitionInfo>, ()>>()?;

    create_composite_disk(
        &partitions,
        &PathBuf::from(zero_filler_path),
        &PathBuf::from(header_path),
        &mut header_file,
        &PathBuf::from(footer_path),
        &mut footer_file,
        &mut composite_image_file,
    )
    .map_err(|e| {
        error!(
            "Failed to create composite disk image at '{}': {}",
            composite_image_path, e
        );
    })?;

    Ok(())
}

#[cfg(feature = "qcow")]
fn create_qcow2(cmd: cmdline::CreateQcow2Command) -> std::result::Result<(), ()> {
    if !(cmd.size.is_some() ^ cmd.backing_file.is_some()) {
        println!(
            "Create a new QCOW2 image at `PATH` of either the specified `SIZE` in bytes or
    with a '--backing_file'."
        );
        return Err(());
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&cmd.file_path)
        .map_err(|e| {
            error!("Failed opening qcow file at '{}': {}", cmd.file_path, e);
        })?;

    match (cmd.size, cmd.backing_file) {
        (Some(size), None) => QcowFile::new(file, size).map_err(|e| {
            error!("Failed to create qcow file at '{}': {}", cmd.file_path, e);
        })?,
        (None, Some(backing_file)) => {
            QcowFile::new_from_backing(file, &backing_file, disk::MAX_NESTING_DEPTH).map_err(
                |e| {
                    error!("Failed to create qcow file at '{}': {}", cmd.file_path, e);
                },
            )?
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn start_device(opts: cmdline::DeviceCommand) -> std::result::Result<(), ()> {
    if let Some(async_executor) = opts.async_executor {
        cros_async::Executor::set_default_executor_kind(async_executor)
            .map_err(|e| error!("Failed to set the default async executor: {:#}", e))?;
    }

    let result = match opts.command {
        cmdline::DeviceSubcommand::CrossPlatform(command) => match command {
            CrossPlatformDevicesCommands::Block(cfg) => run_block_device(cfg),
            #[cfg(feature = "gpu")]
            CrossPlatformDevicesCommands::Gpu(cfg) => run_gpu_device(cfg),
            #[cfg(feature = "net")]
            CrossPlatformDevicesCommands::Net(cfg) => run_net_device(cfg),
            #[cfg(feature = "audio")]
            CrossPlatformDevicesCommands::Snd(cfg) => run_snd_device(cfg),
        },
        cmdline::DeviceSubcommand::Sys(command) => sys::start_device(command),
    };

    result.map_err(|e| {
        error!("Failed to run device: {:#}", e);
    })
}

fn disk_cmd(cmd: cmdline::DiskCommand) -> std::result::Result<(), ()> {
    match cmd.command {
        cmdline::DiskSubcommand::Resize(cmd) => {
            let request = VmRequest::DiskCommand {
                disk_index: cmd.disk_index,
                command: DiskControlCommand::Resize {
                    new_size: cmd.disk_size,
                },
            };
            vms_request(&request, cmd.socket_path)
        }
    }
}

fn make_rt(cmd: cmdline::MakeRTCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::MakeRT, cmd.socket_path)
}

#[cfg(feature = "gpu")]
fn gpu_display_add(cmd: cmdline::GpuAddDisplaysCommand) -> ModifyGpuResult {
    do_gpu_display_add(cmd.socket_path, cmd.gpu_display)
}

#[cfg(feature = "gpu")]
fn gpu_display_list(cmd: cmdline::GpuListDisplaysCommand) -> ModifyGpuResult {
    do_gpu_display_list(cmd.socket_path)
}

#[cfg(feature = "gpu")]
fn gpu_display_remove(cmd: cmdline::GpuRemoveDisplaysCommand) -> ModifyGpuResult {
    do_gpu_display_remove(cmd.socket_path, cmd.display_id)
}

#[cfg(feature = "gpu")]
fn gpu_set_display_mouse_mode(cmd: cmdline::GpuSetDisplayMouseModeCommand) -> ModifyGpuResult {
    do_gpu_set_display_mouse_mode(cmd.socket_path, cmd.display_id, cmd.mouse_mode)
}

#[cfg(feature = "gpu")]
fn modify_gpu(cmd: cmdline::GpuCommand) -> std::result::Result<(), ()> {
    let result = match cmd.command {
        cmdline::GpuSubCommand::AddDisplays(cmd) => gpu_display_add(cmd),
        cmdline::GpuSubCommand::ListDisplays(cmd) => gpu_display_list(cmd),
        cmdline::GpuSubCommand::RemoveDisplays(cmd) => gpu_display_remove(cmd),
        cmdline::GpuSubCommand::SetDisplayMouseMode(cmd) => gpu_set_display_mouse_mode(cmd),
    };
    match result {
        Ok(response) => {
            println!("{}", response);
            Ok(())
        }
        Err(e) => {
            println!("error {}", e);
            Err(())
        }
    }
}

fn usb_attach(cmd: cmdline::UsbAttachCommand) -> ModifyUsbResult<UsbControlResult> {
    let dev_path = Path::new(&cmd.dev_path);

    do_usb_attach(cmd.socket_path, dev_path)
}

fn security_key_attach(cmd: cmdline::UsbAttachKeyCommand) -> ModifyUsbResult<UsbControlResult> {
    let dev_path = Path::new(&cmd.dev_path);

    do_security_key_attach(cmd.socket_path, dev_path)
}

fn usb_detach(cmd: cmdline::UsbDetachCommand) -> ModifyUsbResult<UsbControlResult> {
    do_usb_detach(cmd.socket_path, cmd.port)
}

fn usb_list(cmd: cmdline::UsbListCommand) -> ModifyUsbResult<UsbControlResult> {
    do_usb_list(cmd.socket_path)
}

fn modify_usb(cmd: cmdline::UsbCommand) -> std::result::Result<(), ()> {
    let result = match cmd.command {
        cmdline::UsbSubCommand::Attach(cmd) => usb_attach(cmd),
        cmdline::UsbSubCommand::SecurityKeyAttach(cmd) => security_key_attach(cmd),
        cmdline::UsbSubCommand::Detach(cmd) => usb_detach(cmd),
        cmdline::UsbSubCommand::List(cmd) => usb_list(cmd),
    };
    match result {
        Ok(response) => {
            println!("{}", response);
            Ok(())
        }
        Err(e) => {
            println!("error {}", e);
            Err(())
        }
    }
}

fn snapshot_vm(cmd: cmdline::SnapshotCommand) -> std::result::Result<(), ()> {
    use cmdline::SnapshotSubCommands::*;
    let (socket_path, request) = match cmd.snapshot_command {
        Take(take_cmd) => {
            let req = VmRequest::Snapshot(SnapshotCommand::Take {
                snapshot_path: take_cmd.snapshot_path,
                compress_memory: take_cmd.compress_memory,
                encrypt: take_cmd.encrypt,
            });
            (take_cmd.socket_path, req)
        }
        Restore(path) => {
            let req = VmRequest::Restore(RestoreCommand::Apply {
                restore_path: path.snapshot_path,
                require_encrypted: path.require_encrypted,
            });
            (path.socket_path, req)
        }
    };
    let socket_path = Path::new(&socket_path);
    vms_request(&request, socket_path)
}

#[allow(clippy::unnecessary_wraps)]
fn pkg_version() -> std::result::Result<(), ()> {
    const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
    const PKG_VERSION: Option<&'static str> = option_env!("PKG_VERSION");

    print!("crosvm {}", VERSION.unwrap_or("UNKNOWN"));
    match PKG_VERSION {
        Some(v) => println!("-{}", v),
        None => println!(),
    }
    Ok(())
}

// Returns true if the argument is a flag (e.g. `-s` or `--long`).
//
// As a special case, `-` is not treated as a flag, since it is typically used to represent
// `stdin`/`stdout`.
fn is_flag(arg: &str) -> bool {
    arg.len() > 1 && arg.starts_with('-')
}

// Perform transformations on `args_iter` to produce arguments suitable for parsing by `argh`.
fn prepare_argh_args<I: IntoIterator<Item = String>>(args_iter: I) -> Vec<String> {
    let mut args: Vec<String> = Vec::default();
    // http://b/235882579
    for arg in args_iter {
        match arg.as_str() {
            "--host_ip" => {
                eprintln!("`--host_ip` option is deprecated!");
                eprintln!("Please use `--host-ip` instead");
                args.push("--host-ip".to_string());
            }
            "--balloon_bias_mib" => {
                eprintln!("`--balloon_bias_mib` option is deprecated!");
                eprintln!("Please use `--balloon-bias-mib` instead");
                args.push("--balloon-bias-mib".to_string());
            }
            "-h" => args.push("--help".to_string()),
            arg if is_flag(arg) => {
                // Split `--arg=val` into `--arg val`, since argh doesn't support the former.
                if let Some((key, value)) = arg.split_once("=") {
                    args.push(key.to_string());
                    args.push(value.to_string());
                } else {
                    args.push(arg.to_string());
                }
            }
            arg => args.push(arg.to_string()),
        }
    }

    args
}

fn shorten_usage(help: &str) -> String {
    let mut lines = help.lines().collect::<Vec<_>>();
    let first_line = lines[0].split(char::is_whitespace).collect::<Vec<_>>();

    // Shorten the usage line if it's for `crovm run` command that has so many options.
    let run_usage = format!("Usage: {} run <options> KERNEL", first_line[1]);
    if first_line[0] == "Usage:" && first_line[2] == "run" {
        lines[0] = &run_usage;
    }

    lines.join("\n")
}

fn crosvm_main<I: IntoIterator<Item = String>>(args: I) -> Result<CommandStatus> {
    let _library_watcher = sys::get_library_watcher();

    // The following panic hook will stop our crashpad hook on windows.
    // Only initialize when the crash-pad feature is off.
    #[cfg(not(feature = "crash-report"))]
    sys::set_panic_hook();

    // Ensure all processes detach from metrics on exit.
    #[cfg(windows)]
    let _metrics_destructor = metrics::get_destructor();

    let args = prepare_argh_args(args);
    let args = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
    let args = match crosvm::cmdline::CrosvmCmdlineArgs::from_args(&args[..1], &args[1..]) {
        Ok(args) => args,
        Err(e) if e.status.is_ok() => {
            // If parsing succeeded and the user requested --help, print the usage message to stdout
            // and exit with success.
            let help = shorten_usage(&e.output);
            println!("{help}");
            return Ok(CommandStatus::SuccessOrVmStop);
        }
        Err(e) => {
            error!("arg parsing failed: {}", e.output);
            return Ok(CommandStatus::InvalidArgs);
        }
    };
    let extended_status = args.extended_status;

    debug!("CLI arguments parsed.");

    let mut log_config = LogConfig {
        log_args: LogArgs {
            filter: args.log_level,
            proc_name: args.syslog_tag.unwrap_or("crosvm".to_string()),
            syslog: !args.no_syslog,
            ..Default::default()
        },

        ..Default::default()
    };

    let ret = match args.command {
        Command::CrossPlatform(command) => {
            // Past this point, usage of exit is in danger of leaking zombie processes.
            if let CrossPlatformCommands::Run(cmd) = command {
                if let Some(syslog_tag) = &cmd.syslog_tag {
                    base::warn!(
                        "`crosvm run --syslog-tag` is deprecated; please use \
                         `crosvm --syslog-tag=\"{}\" run` instead",
                        syslog_tag
                    );
                    log_config.log_args.proc_name = syslog_tag.clone();
                }
                // We handle run_vm separately because it does not simply signal success/error
                // but also indicates whether the guest requested reset or stop.
                run_vm(cmd, log_config)
            } else if let CrossPlatformCommands::Device(cmd) = command {
                // On windows, the device command handles its own logging setup, so we can't handle
                // it below otherwise logging will double init.
                if cfg!(unix) {
                    syslog::init_with(log_config).context("failed to initialize syslog")?;
                }
                start_device(cmd)
                    .map_err(|_| anyhow!("start_device subcommand failed"))
                    .map(|_| CommandStatus::SuccessOrVmStop)
            } else {
                syslog::init_with(log_config).context("failed to initialize syslog")?;

                match command {
                    #[cfg(feature = "balloon")]
                    CrossPlatformCommands::Balloon(cmd) => {
                        balloon_vms(cmd).map_err(|_| anyhow!("balloon subcommand failed"))
                    }
                    #[cfg(feature = "balloon")]
                    CrossPlatformCommands::BalloonStats(cmd) => {
                        balloon_stats(cmd).map_err(|_| anyhow!("balloon_stats subcommand failed"))
                    }
                    #[cfg(feature = "balloon")]
                    CrossPlatformCommands::BalloonWs(cmd) => {
                        balloon_ws(cmd).map_err(|_| anyhow!("balloon_ws subcommand failed"))
                    }
                    CrossPlatformCommands::Battery(cmd) => {
                        modify_battery(cmd).map_err(|_| anyhow!("battery subcommand failed"))
                    }
                    #[cfg(feature = "composite-disk")]
                    CrossPlatformCommands::CreateComposite(cmd) => create_composite(cmd)
                        .map_err(|_| anyhow!("create_composite subcommand failed")),
                    #[cfg(feature = "qcow")]
                    CrossPlatformCommands::CreateQcow2(cmd) => {
                        create_qcow2(cmd).map_err(|_| anyhow!("create_qcow2 subcommand failed"))
                    }
                    CrossPlatformCommands::Device(_) => unreachable!(),
                    CrossPlatformCommands::Disk(cmd) => {
                        disk_cmd(cmd).map_err(|_| anyhow!("disk subcommand failed"))
                    }
                    #[cfg(feature = "gpu")]
                    CrossPlatformCommands::Gpu(cmd) => {
                        modify_gpu(cmd).map_err(|_| anyhow!("gpu subcommand failed"))
                    }
                    CrossPlatformCommands::MakeRT(cmd) => {
                        make_rt(cmd).map_err(|_| anyhow!("make_rt subcommand failed"))
                    }
                    CrossPlatformCommands::Resume(cmd) => {
                        resume_vms(cmd).map_err(|_| anyhow!("resume subcommand failed"))
                    }
                    CrossPlatformCommands::Run(_) => unreachable!(),
                    CrossPlatformCommands::Stop(cmd) => {
                        stop_vms(cmd).map_err(|_| anyhow!("stop subcommand failed"))
                    }
                    CrossPlatformCommands::Suspend(cmd) => {
                        suspend_vms(cmd).map_err(|_| anyhow!("suspend subcommand failed"))
                    }
                    CrossPlatformCommands::Swap(cmd) => {
                        swap_vms(cmd).map_err(|_| anyhow!("swap subcommand failed"))
                    }
                    CrossPlatformCommands::Powerbtn(cmd) => {
                        powerbtn_vms(cmd).map_err(|_| anyhow!("powerbtn subcommand failed"))
                    }
                    CrossPlatformCommands::Sleepbtn(cmd) => {
                        sleepbtn_vms(cmd).map_err(|_| anyhow!("sleepbtn subcommand failed"))
                    }
                    CrossPlatformCommands::Gpe(cmd) => {
                        inject_gpe(cmd).map_err(|_| anyhow!("gpe subcommand failed"))
                    }
                    CrossPlatformCommands::Usb(cmd) => {
                        modify_usb(cmd).map_err(|_| anyhow!("usb subcommand failed"))
                    }
                    CrossPlatformCommands::Version(_) => {
                        pkg_version().map_err(|_| anyhow!("version subcommand failed"))
                    }
                    CrossPlatformCommands::Vfio(cmd) => {
                        modify_vfio(cmd).map_err(|_| anyhow!("vfio subcommand failed"))
                    }
                    #[cfg(feature = "pci-hotplug")]
                    CrossPlatformCommands::VirtioNet(cmd) => {
                        modify_virtio_net(cmd).map_err(|_| anyhow!("virtio subcommand failed"))
                    }
                    CrossPlatformCommands::Snapshot(cmd) => {
                        snapshot_vm(cmd).map_err(|_| anyhow!("snapshot subcommand failed"))
                    }
                }
                .map(|_| CommandStatus::SuccessOrVmStop)
            }
        }
        cmdline::Command::Sys(command) => {
            let log_args = log_config.log_args.clone();
            // On windows, the sys commands handle their own logging setup, so we can't handle it
            // below otherwise logging will double init.
            if cfg!(unix) {
                syslog::init_with(log_config).context("failed to initialize syslog")?;
            }
            sys::run_command(command, log_args).map(|_| CommandStatus::SuccessOrVmStop)
        }
    };

    sys::cleanup();

    // WARNING: Any code added after this point is not guaranteed to run
    // since we may forcibly kill this process (and its children) above.
    ret.map(|s| {
        if extended_status {
            s
        } else {
            CommandStatus::SuccessOrVmStop
        }
    })
}

fn main() {
    syslog::early_init();
    debug!("crosvm started.");
    let res = crosvm_main(std::env::args());

    let exit_code = match &res {
        Ok(code) => {
            info!("{}", code.message());
            *code as i32
        }
        Err(e) => {
            let exit_code = error_to_exit_code(&res);
            error!("exiting with error {}: {:?}", exit_code, e);
            exit_code
        }
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_is_flag() {
        assert!(is_flag("--test"));
        assert!(is_flag("-s"));

        assert!(!is_flag("-"));
        assert!(!is_flag("no-leading-dash"));
    }

    #[test]
    fn args_split_long() {
        assert_eq!(
            prepare_argh_args(
                ["crosvm", "run", "--something=options", "vm_kernel"].map(|x| x.to_string())
            ),
            ["crosvm", "run", "--something", "options", "vm_kernel"]
        );
    }

    #[test]
    fn args_split_short() {
        assert_eq!(
            prepare_argh_args(
                ["crosvm", "run", "-p=init=/bin/bash", "vm_kernel"].map(|x| x.to_string())
            ),
            ["crosvm", "run", "-p", "init=/bin/bash", "vm_kernel"]
        );
    }

    #[test]
    fn args_host_ip() {
        assert_eq!(
            prepare_argh_args(
                ["crosvm", "run", "--host_ip", "1.2.3.4", "vm_kernel"].map(|x| x.to_string())
            ),
            ["crosvm", "run", "--host-ip", "1.2.3.4", "vm_kernel"]
        );
    }

    #[test]
    fn args_balloon_bias_mib() {
        assert_eq!(
            prepare_argh_args(
                ["crosvm", "run", "--balloon_bias_mib", "1234", "vm_kernel"].map(|x| x.to_string())
            ),
            ["crosvm", "run", "--balloon-bias-mib", "1234", "vm_kernel"]
        );
    }

    #[test]
    fn args_h() {
        assert_eq!(
            prepare_argh_args(["crosvm", "run", "-h"].map(|x| x.to_string())),
            ["crosvm", "run", "--help"]
        );
    }

    #[test]
    fn args_battery_option() {
        assert_eq!(
            prepare_argh_args(
                [
                    "crosvm",
                    "run",
                    "--battery",
                    "type=goldfish",
                    "-p",
                    "init=/bin/bash",
                    "vm_kernel"
                ]
                .map(|x| x.to_string())
            ),
            [
                "crosvm",
                "run",
                "--battery",
                "type=goldfish",
                "-p",
                "init=/bin/bash",
                "vm_kernel"
            ]
        );
    }

    #[test]
    fn help_success() {
        let args = ["crosvm", "--help"];
        let res = crosvm_main(args.iter().map(|s| s.to_string()));
        let status = res.expect("arg parsing should succeed");
        assert_eq!(status, CommandStatus::SuccessOrVmStop);
    }

    #[test]
    fn invalid_arg_failure() {
        let args = ["crosvm", "--heeeelp"];
        let res = crosvm_main(args.iter().map(|s| s.to_string()));
        let status = res.expect("arg parsing should succeed");
        assert_eq!(status, CommandStatus::InvalidArgs);
    }

    #[test]
    #[cfg(feature = "composite-disk")]
    fn parse_composite_disk_arg() {
        let arg1 = String::from("LABEL1:/partition1.img:writable");
        let res1 = parse_composite_partition_arg(&arg1);
        assert_eq!(
            res1,
            Ok((
                String::from("LABEL1"),
                String::from("/partition1.img"),
                true
            ))
        );

        let arg2 = String::from("LABEL2:/partition2.img");
        let res2 = parse_composite_partition_arg(&arg2);
        assert_eq!(
            res2,
            Ok((
                String::from("LABEL2"),
                String::from("/partition2.img"),
                false
            ))
        );
    }

    #[test]
    fn test_shorten_run_usage() {
        let help = r"Usage: crosvm run [<KERNEL>] [options] <very long line>...

Start a new crosvm instance";
        assert_eq!(
            shorten_usage(help),
            r"Usage: crosvm run <options> KERNEL

Start a new crosvm instance"
        );
    }
}

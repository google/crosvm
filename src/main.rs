// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs a virtual machine

use std::fs::OpenOptions;
use std::path::Path;

use anyhow::{anyhow, Result};
use argh::FromArgs;
use base::syslog::LogConfig;
use base::{error, info, syslog};
use cmdline::{RunCommand, UsbAttachCommand};
mod crosvm;
use crosvm::cmdline;
#[cfg(feature = "plugin")]
use crosvm::config::executable_is_plugin;
use crosvm::config::Config;
use devices::virtio::vhost::user::device::{run_block_device, run_net_device};
use disk::QcowFile;
#[cfg(feature = "composite-disk")]
use disk::{
    create_composite_disk, create_disk_file, create_zero_filler, ImagePartitionType, PartitionInfo,
};
mod sys;
use vm_control::{
    client::{
        do_modify_battery, do_usb_attach, do_usb_detach, do_usb_list, handle_request, vms_request,
        ModifyUsbResult,
    },
    BalloonControlCommand, DiskControlCommand, UsbControlResult, VmRequest, VmResponse,
};

use crate::sys::init_log;
use crosvm::cmdline::{Command, CrossPlatformCommands, CrossPlatformDevicesCommands};

#[cfg(feature = "scudo")]
#[global_allocator]
static ALLOCATOR: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

enum CommandStatus {
    Success,
    VmReset,
    VmStop,
    VmCrash,
    GuestPanic,
}

fn to_command_status(result: Result<sys::ExitState>) -> Result<CommandStatus> {
    match result {
        Ok(sys::ExitState::Stop) => {
            info!("crosvm has exited normally");
            Ok(CommandStatus::VmStop)
        }
        Ok(sys::ExitState::Reset) => {
            info!("crosvm has exited normally due to reset request");
            Ok(CommandStatus::VmReset)
        }
        Ok(sys::ExitState::Crash) => {
            info!("crosvm has exited due to a VM crash");
            Ok(CommandStatus::VmCrash)
        }
        Ok(sys::ExitState::GuestPanic) => {
            info!("crosvm has exited due to a kernel panic in guest");
            Ok(CommandStatus::GuestPanic)
        }
        Err(e) => {
            error!("crosvm has exited with error: {:#}", e);
            Err(e)
        }
    }
}

fn run_vm<F: 'static>(cmd: RunCommand, log_config: LogConfig<F>) -> Result<CommandStatus>
where
    F: Fn(&mut syslog::fmt::Formatter, &log::Record<'_>) -> std::io::Result<()> + Sync + Send,
{
    match TryInto::<Config>::try_into(cmd) {
        #[cfg(feature = "plugin")]
        Ok(cfg) if executable_is_plugin(&cfg.executable_path) => {
            match crosvm::plugin::run_config(cfg) {
                Ok(_) => {
                    info!("crosvm and plugin have exited normally");
                    Ok(CommandStatus::VmStop)
                }
                Err(e) => {
                    error!("{:#}", e);
                    Err(e)
                }
            }
        }
        Ok(cfg) => {
            init_log(log_config, &cfg)?;
            let exit_state = crate::sys::run_config(cfg);
            to_command_status(exit_state)
        }
        Err(e) => {
            error!("{}", e);
            Err(anyhow!("{}", e))
        }
    }
}

fn stop_vms(cmd: cmdline::StopCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Exit, cmd.socket_path)
}

fn suspend_vms(cmd: cmdline::SuspendCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Suspend, cmd.socket_path)
}

fn resume_vms(cmd: cmdline::ResumeCommand) -> std::result::Result<(), ()> {
    vms_request(&VmRequest::Resume, cmd.socket_path)
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

fn balloon_vms(cmd: cmdline::BalloonCommand) -> std::result::Result<(), ()> {
    let command = BalloonControlCommand::Adjust {
        num_bytes: cmd.num_bytes,
    };
    vms_request(&VmRequest::BalloonCommand(command), cmd.socket_path)
}

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
            let request = VmRequest::VfioCommand {
                vfio_path: c.vfio_path.clone(),
                add: true,
                hp_interrupt: true,
            };
            (request, c.socket_path, c.vfio_path)
        }
        cmdline::VfioSubCommand::Remove(c) => {
            let request = VmRequest::VfioCommand {
                vfio_path: c.vfio_path.clone(),
                add: true,
                hp_interrupt: true,
            };
            (request, c.socket_path, c.vfio_path)
        }
    };
    if !vfio_path.exists() || !vfio_path.is_dir() {
        error!("Invalid host sysfs path: {:?}", vfio_path);
        return Err(());
    }
    handle_request(&request, socket_path)?;
    Ok(())
}

#[cfg(feature = "composite-disk")]
fn create_composite(cmd: cmdline::CreateCompositeCommand) -> std::result::Result<(), ()> {
    use std::{fs::File, path::PathBuf};

    let composite_image_path = &cmd.path;
    let zero_filler_path = format!("{}.filler", composite_image_path);
    let header_path = format!("{}.header", composite_image_path);
    let footer_path = format!("{}.footer", composite_image_path);

    let mut composite_image_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&composite_image_path)
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
            if let [label, path] = partition_arg.split(":").collect::<Vec<_>>()[..] {
                let partition_file = File::open(path)
                    .map_err(|e| error!("Failed to open partition image: {}", e))?;

                // Sparseness for composite disks is not user provided on Linux
                // (e.g. via an option), and it has no runtime effect.
                let size = create_disk_file(
                    partition_file,
                    /* is_sparse_file= */ true,
                    disk::MAX_NESTING_DEPTH,
                    Path::new(path),
                )
                .map_err(|e| error!("Failed to create DiskFile instance: {}", e))?
                .get_len()
                .map_err(|e| error!("Failed to get length of partition image: {}", e))?;
                Ok(PartitionInfo {
                    label: label.to_owned(),
                    path: Path::new(path).to_owned(),
                    partition_type: ImagePartitionType::LinuxFilesystem,
                    writable: false,
                    size,
                })
            } else {
                error!(
                    "Must specify label and path for partition '{}', like LABEL:PATH",
                    partition_arg
                );
                Err(())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

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
    let result = match opts.command {
        cmdline::DeviceSubcommand::CrossPlatform(command) => match command {
            CrossPlatformDevicesCommands::Block(cfg) => run_block_device(cfg),
            CrossPlatformDevicesCommands::Net(cfg) => run_net_device(cfg),
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

fn usb_attach(cmd: UsbAttachCommand) -> ModifyUsbResult<UsbControlResult> {
    let dev_path = Path::new(&cmd.dev_path);

    do_usb_attach(cmd.socket_path, dev_path)
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

fn crosvm_main() -> Result<CommandStatus> {
    #[cfg(not(feature = "crash-report"))]
    sys::set_panic_hook();

    let mut args: Vec<String> = Vec::default();
    // http://b/235882579
    for arg in std::env::args() {
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
            // TODO(238361778): This block should work on windows as well.
            #[cfg(unix)]
            arg if arg.starts_with("--") => {
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
    let switch_or_option = [
        "--battery",
        "--video-decoder",
        "--video-encoder",
        "--gpu",
        "--gpu-display",
    ];
    for arg in switch_or_option {
        if let Some(i) = args.iter().position(|a| a == arg) {
            if i == args.len() - 1 || args[i + 1].starts_with("--") {
                args.insert(i + 1, "".to_string());
            }
        }
    }

    let args = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();
    let args = match crosvm::cmdline::CrosvmCmdlineArgs::from_args(&args[..1], &args[1..]) {
        Ok(args) => args,
        Err(e) => {
            println!("{}", e.output);
            return Ok(CommandStatus::Success);
        }
    };
    let extended_status = args.extended_status;

    let log_config = LogConfig {
        filter: &args.log_level,
        syslog: !args.no_syslog,
        ..Default::default()
    };

    let ret = match args.command {
        Command::CrossPlatform(command) => {
            // Past this point, usage of exit is in danger of leaking zombie processes.
            if let CrossPlatformCommands::Run(cmd) = command {
                // We handle run_vm separately because it does not simply signal success/error
                // but also indicates whether the guest requested reset or stop.
                run_vm(cmd, log_config)
            } else {
                syslog::init_with(log_config)
                    .map_err(|e| anyhow!("failed to initialize syslog: {}", e))?;

                match command {
                    CrossPlatformCommands::Balloon(cmd) => {
                        balloon_vms(cmd).map_err(|_| anyhow!("balloon subcommand failed"))
                    }
                    CrossPlatformCommands::BalloonStats(cmd) => {
                        balloon_stats(cmd).map_err(|_| anyhow!("balloon_stats subcommand failed"))
                    }
                    CrossPlatformCommands::Battery(cmd) => {
                        modify_battery(cmd).map_err(|_| anyhow!("battery subcommand failed"))
                    }
                    #[cfg(feature = "composite-disk")]
                    CrossPlatformCommands::CreateComposite(cmd) => create_composite(cmd)
                        .map_err(|_| anyhow!("create_composite subcommand failed")),
                    CrossPlatformCommands::CreateQcow2(cmd) => {
                        create_qcow2(cmd).map_err(|_| anyhow!("create_qcow2 subcommand failed"))
                    }
                    CrossPlatformCommands::Device(cmd) => {
                        start_device(cmd).map_err(|_| anyhow!("start_device subcommand failed"))
                    }
                    CrossPlatformCommands::Disk(cmd) => {
                        disk_cmd(cmd).map_err(|_| anyhow!("disk subcommand failed"))
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
                }
                .map(|_| CommandStatus::Success)
            }
        }
        cmdline::Command::Sys(command) => sys::run_command(command).map(|_| CommandStatus::Success),
    };

    sys::cleanup();

    // WARNING: Any code added after this point is not guaranteed to run
    // since we may forcibly kill this process (and its children) above.
    ret.map(|s| {
        if extended_status {
            s
        } else {
            CommandStatus::Success
        }
    })
}

fn main() {
    let res = crosvm_main();
    let exit_code = match &res {
        Ok(CommandStatus::Success | CommandStatus::VmStop) => {
            info!("exiting with success");
            0
        }
        Ok(CommandStatus::VmReset) => {
            info!("exiting with reset");
            32
        }
        Ok(CommandStatus::VmCrash) => {
            info!("exiting with crash");
            33
        }
        Ok(CommandStatus::GuestPanic) => {
            info!("exiting with guest panic");
            34
        }
        Err(e) => {
            let exit_code = 1;
            error!("exiting with error {}:{:?}", exit_code, e);
            exit_code
        }
    };
    std::process::exit(exit_code);
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::OpenOptions;

use anyhow::anyhow;
use anyhow::Result;
use argh::CommandInfo;
use argh::FromArgs;
use argh::SubCommand;
use base::info;
use base::syslog;
use base::syslog::LogArgs;
use base::syslog::LogConfig;
use base::FromRawDescriptor;
use base::RawDescriptor;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use crosvm_cli::sys::windows::exit::Exit;
use crosvm_cli::sys::windows::exit::ExitContext;
use crosvm_cli::sys::windows::exit::ExitContextAnyhow;
use metrics::MetricEventType;
#[cfg(feature = "slirp")]
use net_util::slirp::sys::windows::SlirpStartupConfig;
use tube_transporter::TubeToken;
use tube_transporter::TubeTransporterReader;
use win_util::DllNotificationData;
use win_util::DllWatcher;

use crate::crosvm::cmdline::RunCommand;
use crate::crosvm::sys::cmdline::Commands;
use crate::crosvm::sys::cmdline::DeviceSubcommand;
use crate::crosvm::sys::cmdline::RunMainCommand;
#[cfg(feature = "slirp")]
use crate::crosvm::sys::cmdline::RunSlirpCommand;
use crate::sys::windows::product::run_metrics;
use crate::CommandStatus;
use crate::Config;

#[cfg(feature = "slirp")]
pub(crate) fn run_slirp(args: RunSlirpCommand) -> Result<()> {
    let raw_transport_tube = args.bootstrap as RawDescriptor;

    let tube_transporter =
        // SAFETY:
        // Safe because we know that raw_transport_tube is valid (passed by inheritance),
        // and that the blocking & framing modes are accurate because we create them ourselves
        // in the broker.
        unsafe { TubeTransporterReader::from_raw_descriptor(raw_transport_tube) };

    let mut tube_data_list = tube_transporter
        .read_tubes()
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    let bootstrap_tube = tube_data_list.get_tube(TubeToken::Bootstrap).unwrap();

    let startup_args: CommonChildStartupArgs =
        bootstrap_tube.recv::<CommonChildStartupArgs>().unwrap();
    let _child_cleanup = common_child_setup(startup_args).exit_context(
        Exit::CommonChildSetupError,
        "failed to perform common child setup",
    )?;

    let slirp_config = bootstrap_tube.recv::<SlirpStartupConfig>().unwrap();

    #[cfg(feature = "sandbox")]
    if let Some(mut target) = sandbox::TargetServices::get()
        .exit_context(Exit::SandboxError, "sandbox operation failed")?
    {
        target.lower_token();
    }

    net_util::Slirp::run_slirp_process(
        slirp_config.slirp_pipe,
        slirp_config.shutdown_event,
        #[cfg(any(feature = "slirp-ring-capture", feature = "slirp-debug"))]
        slirp_config.slirp_capture_file,
    );
    Ok(())
}

pub fn run_broker_impl(cfg: Config, log_args: LogArgs) -> Result<()> {
    cros_tracing::init();
    crate::crosvm::sys::windows::broker::run(cfg, log_args)
}

#[cfg(feature = "sandbox")]
pub fn initialize_sandbox() -> Result<()> {
    if sandbox::is_sandbox_target() {
        // Get the TargetServices pointer so that it gets initialized.
        let _ = sandbox::TargetServices::get()
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }
    Ok(())
}

#[cfg(feature = "sandbox")]
pub fn sandbox_lower_token() -> Result<()> {
    if let Some(mut target) = sandbox::TargetServices::get()
        .exit_context(Exit::SandboxError, "sandbox operation failed")?
    {
        target.lower_token();
    }
    Ok(())
}

fn report_dll_loaded(dll_name: String) {
    metrics::log_event(MetricEventType::DllLoaded(dll_name));
}

pub fn get_library_watcher(
) -> std::io::Result<DllWatcher<impl FnMut(DllNotificationData), impl FnMut(DllNotificationData)>> {
    let mut dlls: HashSet<OsString> = HashSet::new();
    DllWatcher::new(
        move |data| {
            info!("DLL loaded: {:?}", data.base_dll_name);
            if !dlls.insert(data.base_dll_name.clone()) && metrics::is_initialized() {
                report_dll_loaded(data.base_dll_name.to_string_lossy().into_owned());
            }
        },
        |data| info!("DLL unloaded: {:?}", data.base_dll_name),
    )
}

pub(crate) fn start_device(command: DeviceSubcommand) -> Result<()> {
    Err(anyhow!("unknown device name: {:?}", command))
}

pub(crate) fn run_vm_for_broker(args: RunMainCommand) -> Result<()> {
    // This is a noop on unix.
    #[cfg(feature = "sandbox")]
    initialize_sandbox()?;

    let raw_transport_tube = args.bootstrap as RawDescriptor;

    let exit_state = crate::sys::windows::run_config_for_broker(raw_transport_tube)?;
    info!("{}", CommandStatus::from(exit_state).message());
    Ok(())
}

pub(crate) fn cleanup() {
    // We've already cleaned everything up by waiting for all the vcpu threads on windows.
    // TODO: b/142733266. When we sandbox each device, have a way to terminate the other sandboxed
    // processes.
}

fn run_broker(cmd: RunCommand, log_args: LogArgs) -> Result<()> {
    match TryInto::<Config>::try_into(cmd) {
        Ok(cfg) => run_broker_impl(cfg, log_args),
        Err(e) => Err(anyhow!("{}", e)),
    }
}

pub(crate) fn run_command(cmd: Commands, log_args: LogArgs) -> anyhow::Result<()> {
    match cmd {
        Commands::RunMetrics(cmd) => run_metrics(cmd),
        Commands::RunMP(cmd) => run_broker(cmd.run, log_args),
        Commands::RunMain(cmd) => run_vm_for_broker(cmd),
        #[cfg(feature = "slirp")]
        Commands::RunSlirp(cmd) => run_slirp(cmd),
    }
}

pub(crate) fn init_log(log_config: LogConfig, cfg: &Config) -> Result<()> {
    if let Err(e) = syslog::init_with(LogConfig {
        log_args: LogArgs {
            stderr: cfg.log_file.is_none(),
            ..log_config.log_args
        },
        pipe: if let Some(log_file_path) = &cfg.log_file {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file_path)
                .with_exit_context(Exit::LogFile, || {
                    format!("failed to open log file {}", log_file_path)
                })?;
            Some(Box::new(file))
        } else {
            None
        },
        ..log_config
    }) {
        eprintln!("failed to initialize syslog: {}", e);
        return Err(anyhow!("failed to initialize syslog: {}", e));
    }
    Ok(())
}

pub(crate) fn error_to_exit_code(res: &std::result::Result<CommandStatus, anyhow::Error>) -> i32 {
    res.to_exit_code().unwrap_or(Exit::UnknownError.into())
}

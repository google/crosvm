// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Contains the multi-process broker for crosvm. This is a work in progress, and some example
//! structs here are dead code.
#![allow(dead_code)]
use std::boxed::Box;
use std::collections::HashMap;
use std::env::current_exe;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::RawHandle;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base::enable_high_res_timers;
use base::error;
#[cfg(feature = "crash-report")]
use base::generate_uuid;
use base::info;
use base::named_pipes;
use base::syslog;
use base::warn;
use base::AsRawDescriptor;
use base::BlockingMode;
use base::Descriptor;
use base::DuplicateHandleRequest;
use base::DuplicateHandleResponse;
use base::Event;
use base::EventToken;
use base::FramingMode;
use base::RawDescriptor;
use base::ReadNotifier;
use base::RecvTube;
use base::SafeDescriptor;
use base::SendTube;
#[cfg(feature = "gpu")]
use base::StreamChannel;
use base::Timer;
use base::Tube;
use base::WaitContext;
#[cfg(feature = "process-invariants")]
use broker_ipc::init_broker_process_invariants;
use broker_ipc::CommonChildStartupArgs;
#[cfg(feature = "process-invariants")]
use broker_ipc::EmulatorProcessInvariants;
#[cfg(feature = "crash-report")]
use crash_report::product_type;
#[cfg(feature = "crash-report")]
use crash_report::CrashReportAttributes;
use crosvm_cli::bail_exit_code;
use crosvm_cli::ensure_exit_code;
use crosvm_cli::sys::windows::exit::to_process_type_error;
use crosvm_cli::sys::windows::exit::Exit;
use crosvm_cli::sys::windows::exit::ExitCode;
use crosvm_cli::sys::windows::exit::ExitCodeWrapper;
use crosvm_cli::sys::windows::exit::ExitContext;
use crosvm_cli::sys::windows::exit::ExitContextAnyhow;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuBackendConfig;
#[cfg(feature = "gpu")]
use devices::virtio::vhost::user::device::gpu::sys::windows::GpuVmmConfig;
#[cfg(feature = "slirp")]
use devices::virtio::vhost::user::device::NetBackendConfig;
#[cfg(feature = "gpu")]
use gpu_display::EventDevice;
use metrics::protos::event_details::EmulatorChildProcessExitDetails;
use metrics::protos::event_details::RecordDetails;
use metrics::MetricEventType;
#[cfg(feature = "slirp")]
use net_util::slirp::sys::windows::SlirpStartupConfig;
#[cfg(feature = "slirp")]
use net_util::slirp::sys::windows::SLIRP_BUFFER_SIZE;
use serde::Deserialize;
use serde::Serialize;
use tube_transporter::TubeToken;
use tube_transporter::TubeTransferData;
use tube_transporter::TubeTransporter;
use win_util::get_exit_code_process;
use win_util::ProcessType;
use winapi::shared::winerror::ERROR_ACCESS_DENIED;
use winapi::um::processthreadsapi::TerminateProcess;

use crate::sys::windows::get_gpu_product_configs;
use crate::Config;

const KILL_CHILD_EXIT_CODE: u32 = 1;

/// Tubes created by the broker and sent to child processes via the bootstrap tube.
#[derive(Serialize, Deserialize)]
pub struct BrokerTubes {
    pub vm_evt_wrtube: SendTube,
    pub vm_evt_rdtube: RecvTube,
}

/// This struct represents a configured "disk" device as returned by the platform's API. There will
/// be two instances of it for each disk device, with the Tubes connected appropriately. The broker
/// will send one of these to the main process, and the other to the vhost user disk backend.
struct DiskDeviceEnd {
    bootstrap_tube: Tube,
    vhost_user: Tube,
}

/// Example of the function that would be in linux.rs.
fn platform_create_disks(_cfg: Config) -> Vec<(DiskDeviceEnd, DiskDeviceEnd)> {
    unimplemented!()
}

/// Time to wait after a process failure for the remaining processes to exit. When exceeded, all
/// remaining processes, except metrics, will be terminated.
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
/// Time to wait for the metrics process to flush and upload all logs.
const METRICS_TIMEOUT: Duration = Duration::from_secs(3);

/// Maps a process type to its sandbox policy configuration.
#[cfg(feature = "sandbox")]
fn process_policy(process_type: ProcessType, cfg: &Config) -> sandbox::policy::Policy {
    #[allow(unused_mut)]
    let mut policy = match process_type {
        ProcessType::Block => sandbox::policy::BLOCK,
        ProcessType::Main => main_process_policy(cfg),
        ProcessType::Metrics => sandbox::policy::METRICS,
        ProcessType::Net => sandbox::policy::NET,
        ProcessType::Slirp => sandbox::policy::SLIRP,
        ProcessType::Gpu => sandbox::policy::GPU,
    };
    #[cfg(feature = "asan")]
    adjust_asan_policy(&mut policy);
    #[cfg(feature = "cperfetto")]
    adjust_perfetto_policy(&mut policy);
    policy
}

/// Dynamically appends rules to the main process's policy.
#[cfg(feature = "sandbox")]
fn main_process_policy(cfg: &Config) -> sandbox::policy::Policy {
    let mut policy = sandbox::policy::MAIN;
    if let Some(host_guid) = &cfg.host_guid {
        let rule = sandbox::policy::Rule {
            subsystem: sandbox::SubSystem::SUBSYS_FILES,
            semantics: sandbox::Semantics::FILES_ALLOW_ANY,
            pattern: format!("\\??\\pipe\\{}\\vsock-*", host_guid),
        };
        policy.exceptions.push(rule);
    }
    let blocked_dlls = vec![
        "NahimicOSD.dll",
        "XSplitGameSource64.dll",
        "TwitchNativeOverlay64.dll",
        "GridWndHook.dll",
    ];
    for dll in blocked_dlls.iter() {
        policy.dll_blocklist.push(dll.to_string());
    }
    policy
}

/// Adjust a policy to allow ASAN builds to write output files.
#[cfg(feature = "sandbox")]
fn adjust_asan_policy(policy: &mut sandbox::policy::Policy) {
    if (policy.initial_token_level as i32) < (sandbox::TokenLevel::USER_RESTRICTED_NON_ADMIN as i32)
    {
        policy.initial_token_level = sandbox::TokenLevel::USER_RESTRICTED_NON_ADMIN;
    }
    if (policy.integrity_level as i32) > (sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM as i32) {
        policy.integrity_level = sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM;
    }
}

/// Adjust a policy to allow perfetto tracing to open shared memory and use WASAPI.
#[cfg(feature = "sandbox")]
fn adjust_perfetto_policy(policy: &mut sandbox::policy::Policy) {
    if (policy.initial_token_level as i32)
        < (sandbox::TokenLevel::USER_RESTRICTED_SAME_ACCESS as i32)
    {
        policy.initial_token_level = sandbox::TokenLevel::USER_RESTRICTED_SAME_ACCESS;
    }

    if (policy.lockdown_token_level as i32)
        < (sandbox::TokenLevel::USER_RESTRICTED_SAME_ACCESS as i32)
    {
        policy.lockdown_token_level = sandbox::TokenLevel::USER_RESTRICTED_SAME_ACCESS;
    }

    if (policy.integrity_level as i32) > (sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM as i32) {
        policy.integrity_level = sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM;
    }

    if (policy.delayed_integrity_level as i32)
        > (sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM as i32)
    {
        policy.delayed_integrity_level = sandbox::IntegrityLevel::INTEGRITY_LEVEL_MEDIUM;
    }
}

/// Wrapper that terminates a child process (if running) when dropped.
struct ChildCleanup {
    process_type: ProcessType,
    child: Box<dyn Child>,
    dh_tube: Option<Tube>,
}

#[derive(Debug)]
struct UnsandboxedChild(process::Child);
#[derive(Debug)]
struct SandboxedChild(SafeDescriptor);

impl AsRawDescriptor for UnsandboxedChild {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_handle()
    }
}

impl AsRawDescriptor for SandboxedChild {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl Display for ChildCleanup {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?} {:?}", self.process_type, self.child)
    }
}

trait Child: std::fmt::Debug + AsRawDescriptor {
    fn wait(&mut self) -> std::io::Result<Option<ExitCode>>;
    fn try_wait(&mut self) -> std::io::Result<Option<ExitCode>>;
    fn kill(&mut self) -> std::io::Result<()>;
    // Necessary to upcast dyn Child to dyn AsRawDescriptor
    fn as_descriptor(&self) -> &dyn AsRawDescriptor;
}

impl Child for UnsandboxedChild {
    fn wait(&mut self) -> std::io::Result<Option<ExitCode>> {
        Ok(self.0.wait()?.code())
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitCode>> {
        if let Some(status) = self.0.try_wait()? {
            Ok(status.code())
        } else {
            Ok(None)
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.0.kill()
    }

    fn as_descriptor(&self) -> &dyn AsRawDescriptor {
        self
    }
}

impl Child for SandboxedChild {
    fn wait(&mut self) -> std::io::Result<Option<ExitCode>> {
        let wait_ctx = WaitContext::<u32>::new()?;
        wait_ctx.add(&self.0, 0)?;
        let _events = wait_ctx.wait()?;
        self.try_wait()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitCode>> {
        get_exit_code_process(self.0.as_raw_descriptor()).map(|code| code.map(|c| c as i32))
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if unsafe { TerminateProcess(self.0.as_raw_descriptor(), KILL_CHILD_EXIT_CODE) == 0 } {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn as_descriptor(&self) -> &dyn AsRawDescriptor {
        self
    }
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let kill_process = match self.child.try_wait() {
            Ok(None) => true,
            Ok(_) => false,
            Err(_) => true,
        };
        if kill_process {
            if let Err(e) = self.child.kill() {
                const ACCESS_DENIED: Option<i32> = Some(ERROR_ACCESS_DENIED as i32);
                if !matches!(e.raw_os_error(), ACCESS_DENIED) {
                    error!("Failed to clean up child process {}: {}", self, e);
                }
            }

            // Sending a kill signal does NOT imply the process has exited. Wait for it to exit.
            let wait_res = self.child.wait();
            if let Ok(Some(code)) = wait_res.as_ref() {
                warn!(
                    "child process {} killed, exited {}",
                    self,
                    ExitCodeWrapper(*code)
                );
            } else {
                error!(
                    "failed to wait for child process {} that was terminated: {:?}",
                    self, wait_res
                );
            }
        } else {
            info!("child process {} already terminated", self);
        }

        // Log child exit code regardless of whether we killed it or it exited
        // on its own.
        {
            // Don't even attempt to log metrics process, it doesn't exist to log
            // itself.
            if self.process_type != ProcessType::Metrics {
                let exit_code = self.child.wait();
                if let Ok(Some(exit_code)) = exit_code {
                    let mut details = RecordDetails::new();
                    let mut exit_details = EmulatorChildProcessExitDetails::new();
                    exit_details.set_exit_code(exit_code as u32);
                    exit_details.set_process_type(self.process_type.into());
                    details.set_emulator_child_process_exit_details(exit_details);
                    metrics::log_event_with_details(MetricEventType::ChildProcessExit, &details);
                } else {
                    error!(
                        "Failed to log exit code for process: {:?}, couldn't get exit code",
                        self.process_type
                    );
                }
            }
        }
    }
}

/// Represents a child process spawned by the broker.
struct ChildProcess {
    // This is unused, but we hold it open to avoid an EPIPE in the child if it doesn't
    // immediately read its startup information. We don't use FlushFileBuffers to avoid this because
    // that would require blocking the startup sequence.
    tube_transporter: TubeTransporter,

    // Used to set up the child process. Unused in steady state.
    bootstrap_tube: Tube,
    // Child process PID.
    process_id: u32,
    alias_pid: u32,
}

/// Wrapper to start the broker.
pub fn run(cfg: Config) -> Result<()> {
    // This wrapper exists because errors that are returned up to the caller aren't logged, though
    // they are used to generate the return code. For practical debugging though, we want to log the
    // errors.
    let res = run_internal(cfg);
    if let Err(e) = &res {
        error!("Broker encountered an error: {}", e);
    }
    res
}

#[derive(EventToken)]
enum Token {
    Sigterm,
    Process(u32),
    MainExitTimeout,
    DeviceExitTimeout,
    MetricsExitTimeout,
    SigtermTimeout,
    DuplicateHandle(u32),
}

fn get_log_path(cfg: &Config, file_name: &str) -> Option<PathBuf> {
    cfg.logs_directory
        .as_ref()
        .map(|dir| Path::new(dir).join(file_name))
}

/// Creates a metrics tube pair for communication with the metrics process.
/// The returned Tube will be used by the process producing logs, while
/// the metric_tubes list is sent to the metrics process to receive logs.
///
/// IMPORTANT NOTE: The metrics process must receive the client (second) end
/// of the Tube pair in order to allow the connection to be properly shut
/// down without data loss.
fn metrics_tube_pair(metric_tubes: &mut Vec<Tube>) -> Result<Tube> {
    // TODO(nkgold): as written, this Tube pair won't handle ancillary data properly because the
    // PIDs are not set properly at each end; however, we don't plan to send ancillary data.
    let (t1, t2) = Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
    metric_tubes.push(t2);
    Ok(t1)
}

#[cfg(feature = "crash-report")]
pub fn create_crash_report_attrs(cfg: &Config, product_type: &str) -> CrashReportAttributes {
    crash_report::CrashReportAttributes {
        product_type: product_type.to_owned(),
        pipe_name: cfg.crash_pipe_name.clone(),
        report_uuid: cfg.crash_report_uuid.clone(),
        product_name: cfg.product_name.clone(),
        product_version: cfg.product_version.clone(),
    }
}

/// Setup crash reporting for a process. Each process MUST provide a unique `product_type` to avoid
/// making crash reports incomprehensible.
#[cfg(feature = "crash-report")]
pub fn setup_emulator_crash_reporting(cfg: &Config) -> Result<String> {
    crash_report::setup_crash_reporting(create_crash_report_attrs(
        cfg,
        crash_report::product_type::EMULATOR,
    ))
    .exit_context(
        Exit::CrashReportingInit,
        "failed to initialize crash reporting",
    )
}

/// Starts the broker, which in turn spawns the main process & vhost user devices.
/// General data flow for device & main process spawning:
///   Each platform (e.g. linux.rs) will provide create_inputs/gpus/nets.
///
///   Those functions will return a list of pairs of structs (containing the pipes and other
///   process specific configuration) for the VMM & backend sides of the device. These structs
///   should be minimal, and not duplicate information that is otherwise available in the Config
///   struct. There MAY be two different types per device, one for the VMM side, and another for
///   the backend.
///
///   The broker will send all the VMM structs to the main process, and the other structs
///   to the vhost user backends. Every process will get a copy of the Config struct.
///
///   Finally, the broker will wait on the child processes to exit, and handle errors.
///
/// Refrain from using platform specific code within this function. It will eventually be cross
/// platform.
fn run_internal(mut cfg: Config) -> Result<()> {
    #[cfg(feature = "sandbox")]
    if sandbox::is_sandbox_broker() {
        // Get the BrokerServices pointer so that it gets initialized.
        sandbox::BrokerServices::get()
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }
    // Note that parsing args causes syslog's log file to be set to the log file for the "main"
    // process. We don't want broker logs going there, so we fetch our own log file and set it here.
    let mut log_cfg = syslog::LogConfig::default();
    if let Some(log_path) = get_log_path(&cfg, "broker_syslog.log") {
        log_cfg.pipe = Some(Box::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_path.as_path())
                .with_exit_context(Exit::LogFile, || {
                    format!("failed to open log file {}", log_path.display())
                })?,
        ));
        log_cfg.stderr = false;
    } else {
        log_cfg.stderr = true;
    }
    syslog::init_with(log_cfg)?;

    #[cfg(feature = "process-invariants")]
    let process_invariants = init_broker_process_invariants(
        &cfg.process_invariants_data_handle,
        &cfg.process_invariants_data_size,
    )
    .exit_context(
        Exit::ProcessInvariantsInit,
        "failed to initialize process invariants",
    )?;

    #[cfg(feature = "crash-report")]
    init_broker_crash_reporting(&mut cfg)?;

    let _raise_timer_resolution = enable_high_res_timers()
        .exit_context(Exit::EnableHighResTimer, "failed to enable high res timers")?;

    // Note: in case of an error / scope exit, any children still in this map will be automatically
    // closed.
    let mut children: HashMap<u32, ChildCleanup> = HashMap::new();

    let mut exit_events = Vec::new();
    let mut wait_ctx: WaitContext<Token> = WaitContext::new()
        .exit_context(Exit::CreateWaitContext, "failed to create event context")?;

    // Hook ^C / SIGTERM so we can handle it gracefully.
    let sigterm_event = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
    let sigterm_event_ctrlc = sigterm_event
        .try_clone()
        .exit_context(Exit::CloneEvent, "failed to clone event")?;
    ctrlc::set_handler(move || {
        sigterm_event_ctrlc.signal().unwrap();
    })
    .exit_context(Exit::SetSigintHandler, "failed to set sigint handler")?;
    wait_ctx.add(&sigterm_event, Token::Sigterm).exit_context(
        Exit::WaitContextAdd,
        "failed to add trigger to event context",
    )?;

    let mut metric_tubes = Vec::new();
    let metrics_controller = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["run-metrics"],
        get_log_path(&cfg, "metrics_stdout.log"),
        get_log_path(&cfg, "metrics_stderr.log"),
        ProcessType::Metrics,
        &mut children,
        &mut wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */
        cfg.jail_config.is_some(),
        Vec::new(),
        &cfg,
    )?;
    metrics_controller
        .tube_transporter
        .serialize_and_transport(metrics_controller.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    let mut main_child = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["run-main"],
        get_log_path(&cfg, "main_stdout.log"),
        get_log_path(&cfg, "main_stderr.log"),
        ProcessType::Main,
        &mut children,
        &mut wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */
        cfg.jail_config.is_some(),
        Vec::new(),
        &cfg,
    )?;

    // Save block children `ChildProcess` so TubeTransporter and Tubes don't get closed.
    let _block_children = start_up_block_backends(
        &mut cfg,
        &mut children,
        &mut exit_events,
        &mut wait_ctx,
        &mut main_child,
        &mut metric_tubes,
        #[cfg(feature = "process-invariants")]
        &process_invariants,
    )?;

    #[cfg(feature = "slirp")]
    let (_slirp_child, _net_children) = start_up_net_backend(
        &mut main_child,
        &mut children,
        &mut exit_events,
        &mut wait_ctx,
        &mut cfg,
        &mut metric_tubes,
        #[cfg(feature = "process-invariants")]
        &process_invariants,
    )?;

    let (vm_evt_wrtube, vm_evt_rdtube) =
        Tube::directional_pair().context("failed to create vm event tube")?;

    #[cfg(feature = "gpu")]
    let gpu_cfg = platform_create_gpu(
        &cfg,
        &mut main_child,
        &mut exit_events,
        vm_evt_wrtube
            .try_clone()
            .exit_context(Exit::CloneEvent, "failed to clone event")?,
    )?;

    #[cfg(feature = "gpu")]
    let _gpu_child = if cfg.vhost_user_gpu.is_empty() {
        // Pass both backend and frontend configs to main process.
        cfg.gpu_backend_config = Some(gpu_cfg.0);
        cfg.gpu_vmm_config = Some(gpu_cfg.1);
        None
    } else {
        Some(start_up_gpu(
            &mut cfg,
            gpu_cfg,
            &mut main_child,
            &mut children,
            &mut wait_ctx,
            &mut metric_tubes,
            #[cfg(feature = "process-invariants")]
            &process_invariants,
        )?)
    };

    // Wait until all device processes are spun up so main TubeTransporter will have all the
    // device control and Vhost tubes.
    main_child
        .tube_transporter
        .serialize_and_transport(main_child.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;
    main_child.bootstrap_tube.send(&cfg).unwrap();

    let main_startup_args = CommonChildStartupArgs::new(
        get_log_path(&cfg, "main_syslog.log"),
        #[cfg(feature = "crash-report")]
        create_crash_report_attrs(&cfg, product_type::EMULATOR),
        #[cfg(feature = "process-invariants")]
        process_invariants.clone(),
        Some(metrics_tube_pair(&mut metric_tubes)?),
    )?;
    main_child.bootstrap_tube.send(&main_startup_args).unwrap();

    let exit_event = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
    main_child.bootstrap_tube.send(&exit_event).unwrap();
    exit_events.push(exit_event);

    let broker_tubes = BrokerTubes {
        vm_evt_wrtube,
        vm_evt_rdtube,
    };
    main_child.bootstrap_tube.send(&broker_tubes).unwrap();

    // Setup our own metrics agent
    {
        let broker_metrics = metrics_tube_pair(&mut metric_tubes)?;
        metrics::initialize(broker_metrics);
        let use_vulkan = if cfg!(feature = "gpu") {
            match &cfg.gpu_parameters {
                Some(params) => Some(params.use_vulkan),
                None => {
                    warn!("No GPU parameters set on crosvm config.");
                    None
                }
            }
        } else {
            None
        };
        anti_tamper::setup_common_metric_invariants(
            &cfg.product_version,
            &cfg.product_channel,
            &use_vulkan.unwrap_or_default(),
        );
    }

    // We have all the metrics tubes from other children, so give them to the metrics controller
    // along with a startup configuration.
    let metrics_startup_args = CommonChildStartupArgs::new(
        get_log_path(&cfg, "metrics_syslog.log"),
        #[cfg(feature = "crash-report")]
        create_crash_report_attrs(&cfg, product_type::METRICS),
        #[cfg(feature = "process-invariants")]
        process_invariants.clone(),
        None,
    )?;
    metrics_controller
        .bootstrap_tube
        .send(&metrics_startup_args)
        .unwrap();

    metrics_controller
        .bootstrap_tube
        .send(&metric_tubes)
        .unwrap();

    Supervisor::broker_supervise_loop(children, wait_ctx, exit_events)
}

/// Shuts down the metrics process, waiting for it to close to ensure
/// all logs are flushed.
fn clean_up_metrics(metrics_child: ChildCleanup) -> Result<()> {
    // This will close the final metrics connection, triggering a metrics
    // process shutdown.
    metrics::get_destructor().cleanup();

    // However, we still want to wait for the metrics process to finish
    // flushing any pending logs before exiting.
    let metrics_cleanup_wait = WaitContext::<u32>::new().exit_context(
        Exit::CreateWaitContext,
        "failed to create metrics wait context",
    )?;
    let mut metrics_timeout =
        Timer::new().exit_context(Exit::CreateTimer, "failed to create metrics timeout timer")?;
    metrics_timeout
        .reset(EXIT_TIMEOUT, None)
        .exit_context(Exit::ResetTimer, "failed to reset timer")?;
    metrics_cleanup_wait.add(&metrics_timeout, 0).exit_context(
        Exit::WaitContextAdd,
        "failed to add metrics timout to wait context",
    )?;
    metrics_cleanup_wait
        .add(metrics_child.child.as_descriptor(), 1)
        .exit_context(
            Exit::WaitContextAdd,
            "failed to add metrics process to wait context",
        )?;
    let events = metrics_cleanup_wait
        .wait()
        .context("failed to wait for metrics context")?;

    let mut process_exited = false;
    if events.iter().any(|e| e.is_readable && e.token == 1) {
        process_exited = true;
    }

    if !process_exited {
        warn!(
            "broker: Metrics process timed out before cleanly exiting.
            This may indicate some logs remain unsent."
        );
        // Process will be force-killed on drop
    }

    Ok(())
}

#[cfg(feature = "crash-report")]
fn init_broker_crash_reporting(cfg: &mut Config) -> Result<()> {
    cfg.crash_report_uuid = Some(generate_uuid());
    if cfg.crash_pipe_name.is_none() {
        // We weren't started by the service. Spin up a crash reporter to be shared with all
        // children.
        cfg.crash_pipe_name = Some(
            crash_report::setup_crash_reporting(create_crash_report_attrs(
                cfg,
                product_type::BROKER,
            ))
            .exit_context(Exit::CrashReportingInit, "failed to init crash reporting")?,
        );
    } else {
        crash_report::setup_crash_reporting(create_crash_report_attrs(cfg, product_type::BROKER))
            .exit_context(Exit::CrashReportingInit, "failed to init crash reporting")?;
    }

    Ok(())
}

struct Supervisor {
    children: HashMap<u32, ChildCleanup>,
    wait_ctx: WaitContext<Token>,
    exit_events: Vec<Event>,
    exit_timer: Option<Timer>,
}

impl Supervisor {
    pub fn broker_supervise_loop(
        children: HashMap<u32, ChildCleanup>,
        wait_ctx: WaitContext<Token>,
        exit_events: Vec<Event>,
    ) -> Result<()> {
        let mut supervisor = Supervisor {
            children,
            wait_ctx,
            exit_events,
            exit_timer: None,
        };
        let result = supervisor.broker_loop();

        // Once supervise loop exits, we are exiting and just need to clean
        // up. In error cases, there could still be children processes, so we close
        // those first, and finally drop the metrics process.
        supervisor.children.retain(|_, child| {
            match child.process_type {
                ProcessType::Metrics => true,
                _ => {
                    warn!(
                        "broker: Forcibly closing child (type: {:?}). This often means
                        the child was unable to close within the normal timeout window,
                        or the broker itself failed with an error.",
                        child.process_type
                    );
                    // Child killed on drop
                    false
                }
            }
        });

        {
            if supervisor.is_only_metrics_process_running() {
                clean_up_metrics(supervisor.children.into_values().next().unwrap())?;
            } else {
                warn!(
                    "broker: Metrics process not running after cleanup.
                    This may indicate some exit logs have been dropped."
                );
            }
        }

        result
    }

    /// We require exactly one main process.
    fn assert_children_sane(&mut self) {
        let main_processes = self
            .children
            .iter()
            .filter(|(_, child)| child.process_type == ProcessType::Main)
            .count();
        if main_processes != 1 {
            // Why do we have to clear children? Well, panic *can* cause destructors not to run,
            // which means these children won't run. The exact explanation for this isn't clear, but
            // it reproduced consistently. So since we're panicking, we'll be careful.
            self.children.clear();
            panic!(
                "Broker must supervise exactly one main process. Got {} main process(es).",
                main_processes,
            )
        }
    }

    fn is_only_metrics_process_running(&self) -> bool {
        self.children.len() == 1
            && self.children.values().next().unwrap().process_type == ProcessType::Metrics
    }

    fn all_non_metrics_processes_exited(&self) -> bool {
        self.children.len() == 0 || self.is_only_metrics_process_running()
    }

    fn start_exit_timer(&mut self, timeout_token: Token) -> Result<()> {
        if self.exit_timer.is_some() {
            return Ok(());
        }

        let mut et = Timer::new().exit_context(Exit::CreateTimer, "failed to create timer")?;
        et.reset(EXIT_TIMEOUT, None)
            .exit_context(Exit::ResetTimer, "failed to reset timer")?;
        self.wait_ctx.add(&et, timeout_token).exit_context(
            Exit::WaitContextAdd,
            "failed to add trigger to wait context",
        )?;
        self.exit_timer = Some(et);

        Ok(())
    }

    /// Once children have been spawned, this function is called to run the supervision loop, which
    /// waits for processes to exit and handles errors.
    fn broker_loop(&mut self) -> Result<()> {
        const KILLED_BY_SIGNAL: ExitCode = Exit::KilledBySignal as ExitCode;
        self.assert_children_sane();
        let mut first_nonzero_exitcode = None;

        while !self.all_non_metrics_processes_exited() {
            let events = self
                .wait_ctx
                .wait()
                .context("failed to wait for event context")?;

            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::Sigterm => {
                        // Signal all children other than metrics to exit.
                        for exit_event in &self.exit_events {
                            if let Err(e) = exit_event.signal() {
                                error!("failed to signal exit event to child: {}", e);
                            }
                        }
                        first_nonzero_exitcode.get_or_insert(KILLED_BY_SIGNAL);
                        self.start_exit_timer(Token::SigtermTimeout)?;
                    }
                    Token::Process(child_id) => {
                        let mut child = self.children.remove(&child_id).unwrap();
                        let process_handle = Descriptor(child.child.as_raw_descriptor());
                        self.wait_ctx.delete(&process_handle).exit_context(
                            Exit::WaitContextDelete,
                            "failed to remove trigger from event context",
                        )?;
                        if let Some(dh_tube) = child.dh_tube.as_ref() {
                            self.wait_ctx
                                .delete(dh_tube.get_read_notifier())
                                .exit_context(
                                    Exit::WaitContextDelete,
                                    "failed to remove trigger from event context",
                                )?;
                        }

                        let exit_code = child.child.wait().unwrap().unwrap();
                        info!(
                            "broker: child (type {:?}) exited {}",
                            child.process_type,
                            ExitCodeWrapper(exit_code),
                        );

                        // Save the child's exit code (to pass through to the broker's exit code) if
                        // none has been saved or if the previously saved exit code was
                        // KilledBySignal.  We overwrite KilledBySignal because the child exit may
                        // race with the sigterm from the service, esp if child exit is slowed by a Crashpad
                        // dump, and we don't want to lose the child's exit code if it was the
                        // initial cause of the emulator failing.
                        if exit_code != 0
                            && (first_nonzero_exitcode.is_none()
                                || matches!(first_nonzero_exitcode, Some(KILLED_BY_SIGNAL)))
                        {
                            info!(
                                "setting first_nonzero_exitcode {:?} -> {}",
                                first_nonzero_exitcode, exit_code,
                            );
                            first_nonzero_exitcode =
                                Some(to_process_type_error(exit_code as u32, child.process_type)
                                    as i32);
                        }

                        let timeout_token = match child.process_type {
                            ProcessType::Main => Token::MainExitTimeout,
                            ProcessType::Metrics => Token::MetricsExitTimeout,
                            _ => Token::DeviceExitTimeout,
                        };
                        self.start_exit_timer(timeout_token)?;
                    }
                    Token::SigtermTimeout => {
                        if let Some(exit_code) = first_nonzero_exitcode {
                            if exit_code != KILLED_BY_SIGNAL {
                                bail_exit_code!(
                                    exit_code,
                                    "broker got sigterm, but a child exited with an error.",
                                );
                            }
                        }
                        ensure_exit_code!(
                            self.all_non_metrics_processes_exited(),
                            Exit::BrokerSigtermTimeout,
                            "broker got sigterm, but other broker children did not exit within the \
                            timeout",
                        );
                    }
                    Token::MainExitTimeout => {
                        if let Some(exit_code) = first_nonzero_exitcode {
                            bail_exit_code!(
                                exit_code,
                                "main exited, but a child exited with an error.",
                            );
                        }
                        ensure_exit_code!(
                            self.all_non_metrics_processes_exited(),
                            Exit::BrokerMainExitedTimeout,
                            "main exited, but other broker children did not exit within the \
                            timeout",
                        );
                    }
                    Token::DeviceExitTimeout => {
                        // A device process exited, but there are still other processes running.
                        if let Some(exit_code) = first_nonzero_exitcode {
                            bail_exit_code!(
                                exit_code,
                                "a device exited, and either it or another child exited with an \
                                error.",
                            );
                        }
                        ensure_exit_code!(
                            self.all_non_metrics_processes_exited(),
                            Exit::BrokerDeviceExitedTimeout,
                            "device exited, but other broker children did not exit within the \
                            timeout",
                        );
                    }
                    Token::MetricsExitTimeout => {
                        // The metrics server exited, but there are still other processes running.
                        if let Some(exit_code) = first_nonzero_exitcode {
                            bail_exit_code!(
                                exit_code,
                                "metrics server exited, and either it or another child exited with \
                                an error.",
                            );
                        }
                        ensure_exit_code!(
                            self.children.len() == 0,
                            Exit::BrokerMetricsExitedTimeout,
                            "metrics exited, but other broker children did not exit within the \
                            timeout",
                        );
                    }
                    Token::DuplicateHandle(child_id) => {
                        if let Some(tube) = &self.children[&child_id].dh_tube {
                            let req: DuplicateHandleRequest = tube
                                .recv()
                                .exit_context(Exit::TubeFailure, "failed operation on tube")?;
                            if !self.children.contains_key(&req.target_alias_pid) {
                                error!(
                                    "DuplicateHandleRequest contained invalid alias pid: {}",
                                    req.target_alias_pid
                                );
                                tube.send(&DuplicateHandleResponse { handle: None })
                                    .exit_context(Exit::TubeFailure, "failed operation on tube")?;
                            } else {
                                let target = &self.children[&req.target_alias_pid].child;
                                let handle = win_util::duplicate_handle_from_source_process(
                                    self.children[&child_id].child.as_raw_descriptor(),
                                    req.handle as RawHandle,
                                    target.as_raw_descriptor(),
                                );
                                match handle {
                                    Ok(handle) => tube
                                        .send(&DuplicateHandleResponse {
                                            handle: Some(handle as usize),
                                        })
                                        .exit_context(
                                            Exit::TubeFailure,
                                            "failed operation on tube",
                                        )?,
                                    Err(e) => {
                                        error!("Failed to duplicate handle: {}", e);
                                        tube.send(&DuplicateHandleResponse { handle: None })
                                            .exit_context(
                                                Exit::TubeFailure,
                                                "failed operation on tube",
                                            )?
                                    }
                                };
                            }
                        }
                    }
                }
            }
        }

        if let Some(exit_code) = first_nonzero_exitcode {
            bail_exit_code!(
                exit_code,
                if exit_code == KILLED_BY_SIGNAL {
                    "broker got sigterm, and all children exited zero from shutdown event."
                } else {
                    "all processes exited, but at least one encountered an error."
                },
            );
        }

        Ok(())
    }
}

fn start_up_block_backends(
    cfg: &mut Config,
    children: &mut HashMap<u32, ChildCleanup>,
    exit_events: &mut Vec<Event>,
    wait_ctx: &mut WaitContext<Token>,
    main_child: &mut ChildProcess,
    metric_tubes: &mut Vec<Tube>,
    #[cfg(feature = "process-invariants")] process_invariants: &EmulatorProcessInvariants,
) -> Result<Vec<ChildProcess>> {
    let mut block_children = Vec::new();
    let disk_options = cfg.disks.clone();
    for (index, disk_option) in disk_options.iter().enumerate() {
        let block_child = spawn_block_backend(index, main_child, children, wait_ctx, cfg)?;

        let startup_args = CommonChildStartupArgs::new(
            get_log_path(cfg, &format!("disk_{}_syslog.log", index)),
            #[cfg(feature = "crash-report")]
            create_crash_report_attrs(cfg, &format!("{}_{}", product_type::DISK, index)),
            #[cfg(feature = "process-invariants")]
            process_invariants.clone(),
            Some(metrics_tube_pair(metric_tubes)?),
        )?;
        block_child.bootstrap_tube.send(&startup_args).unwrap();

        block_child.bootstrap_tube.send(&disk_option).unwrap();

        let exit_event = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
        block_child.bootstrap_tube.send(&exit_event).unwrap();
        exit_events.push(exit_event);
        block_children.push(block_child);
    }

    Ok(block_children)
}

fn spawn_block_backend(
    log_index: usize,
    main_child: &mut ChildProcess,
    children: &mut HashMap<u32, ChildCleanup>,
    wait_ctx: &mut WaitContext<Token>,
    cfg: &mut Config,
) -> Result<ChildProcess> {
    let (mut vhost_user_main_tube, mut vhost_user_device_tube) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

    let (mut disk_host_tube, mut disk_device_tube) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

    disk_device_tube.set_target_pid(main_child.alias_pid);
    vhost_user_device_tube.set_target_pid(main_child.alias_pid);
    let block_child = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["device", "block"],
        get_log_path(cfg, &format!("disk_{}_stdout.log", log_index)),
        get_log_path(cfg, &format!("disk_{}_stderr.log", log_index)),
        ProcessType::Block,
        children,
        wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */
        cfg.jail_config.is_some(),
        vec![
            TubeTransferData {
                tube: disk_device_tube,
                tube_token: TubeToken::Control,
            },
            TubeTransferData {
                tube: vhost_user_device_tube,
                tube_token: TubeToken::VhostUser,
            },
        ],
        cfg,
    )?;

    block_child
        .tube_transporter
        .serialize_and_transport(block_child.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    vhost_user_main_tube.set_target_pid(block_child.alias_pid);
    disk_host_tube.set_target_pid(block_child.alias_pid);
    cfg.block_control_tube.push(disk_host_tube);
    cfg.block_vhost_user_tube.push(vhost_user_main_tube);

    Ok(block_child)
}

#[cfg(feature = "sandbox")]
fn spawn_sandboxed_child<I, S>(
    program: &str,
    args: I,
    stdout_file: Option<std::fs::File>,
    stderr_file: Option<std::fs::File>,
    handles_to_inherit: Vec<&dyn AsRawDescriptor>,
    process_policy: sandbox::policy::Policy,
) -> Result<(u32, Box<dyn Child>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut broker = sandbox::BrokerServices::get()
        .exit_context(Exit::SandboxError, "sandbox operation failed")?
        .unwrap();
    let mut policy = broker.create_policy();
    policy
        .set_token_level(
            process_policy.initial_token_level,
            process_policy.lockdown_token_level,
        )
        .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    policy
        .set_job_level(process_policy.job_level, process_policy.ui_exceptions)
        .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    policy
        .set_integrity_level(process_policy.integrity_level)
        .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    policy
        .set_delayed_integrity_level(process_policy.delayed_integrity_level)
        .exit_context(Exit::SandboxError, "sandbox operation failed")?;

    if process_policy.alternate_desktop {
        policy
            .set_alternate_desktop(process_policy.alternate_winstation)
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }

    for rule in process_policy.exceptions {
        policy
            .add_rule(rule.subsystem, rule.semantics, rule.pattern)
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }

    policy.set_lockdown_default_dacl();

    if let Some(file) = stdout_file.as_ref() {
        policy
            .set_stdout_from_file(file)
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }

    if let Some(file) = stderr_file.as_ref() {
        policy
            .set_stderr_from_file(file)
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }

    for handle in handles_to_inherit.into_iter() {
        policy.add_handle_to_share(handle);
    }

    for dll in process_policy.dll_blocklist.into_iter() {
        policy
            .add_dll_to_unload(&dll)
            .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    }

    // spawn_target uses CreateProcessW to create a new process, which will pass
    // the command line arguments verbatim to the new process. Most processes
    // expect that argv[0] will be the program name, so provide that before the
    // rest of the args.
    let command_line = args
        .into_iter()
        .fold(format!("\"{}\"", program), |mut args, arg| {
            args.push(' ');
            args.push_str(OsStr::new(&arg).to_str().unwrap());
            args
        });

    let (target, warning) = broker
        .spawn_target(program, &command_line, &policy)
        .exit_context(Exit::SandboxError, "sandbox operation failed")?;
    if let Some(w) = warning {
        warn!("sandbox: got warning spawning target: {}", w);
    }
    win_util::resume_thread(target.thread.as_raw_descriptor())
        .exit_context(Exit::ProcessSpawnFailed, "failed to spawn child process")?;

    Ok((target.process_id, Box::new(SandboxedChild(target.process))))
}

fn spawn_unsandboxed_child<I, S>(
    program: &str,
    args: I,
    stdout_file: Option<std::fs::File>,
    stderr_file: Option<std::fs::File>,
    handles_to_inherit: Vec<&dyn AsRawDescriptor>,
) -> Result<(u32, Box<dyn Child>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut proc = Command::new(program);

    let proc = proc.args(args);

    for handle in handles_to_inherit.iter() {
        win_util::set_handle_inheritance(handle.as_raw_descriptor(), /* inheritable= */ true)
            .exit_context(Exit::CreateSocket, "failed to create socket")?;
    }

    if let Some(file) = stdout_file {
        proc.stdout(file);
    }

    if let Some(file) = stderr_file {
        proc.stderr(file);
    }

    info!("spawning process: {:?}", proc);
    let proc = proc
        .spawn()
        .exit_context(Exit::ProcessSpawnFailed, "failed to spawn child process")?;

    for handle in handles_to_inherit.iter() {
        win_util::set_handle_inheritance(handle.as_raw_descriptor(), /* inheritable= */ false)
            .exit_context(Exit::CreateSocket, "failed to create socket")?;
    }

    let process_id = proc.id();

    Ok((process_id, Box::new(UnsandboxedChild(proc))))
}

#[cfg(feature = "slirp")]
fn start_up_net_backend(
    main_child: &mut ChildProcess,
    children: &mut HashMap<u32, ChildCleanup>,
    exit_events: &mut Vec<Event>,
    wait_ctx: &mut WaitContext<Token>,
    cfg: &mut Config,
    metric_tubes: &mut Vec<Tube>,
    #[cfg(feature = "process-invariants")] process_invariants: &EmulatorProcessInvariants,
) -> Result<(ChildProcess, ChildProcess)> {
    let (host_pipe, guest_pipe) = named_pipes::pair_with_buffer_size(
        &FramingMode::Message.into(),
        &BlockingMode::Blocking.into(),
        /* timeout= */ 0,
        /* buffer_size= */ SLIRP_BUFFER_SIZE,
        /* overlapped= */ true,
    )
    .expect("Failed to create named pipe pair.");
    let slirp_kill_event = Event::new().expect("Failed to create slirp kill event.");

    let slirp_child = spawn_slirp(children, wait_ctx, cfg)?;

    let slirp_child_startup_args = CommonChildStartupArgs::new(
        get_log_path(cfg, "slirp_syslog.log"),
        #[cfg(feature = "crash-report")]
        create_crash_report_attrs(cfg, product_type::SLIRP),
        #[cfg(feature = "process-invariants")]
        process_invariants.clone(),
        Some(metrics_tube_pair(metric_tubes)?),
    )?;
    slirp_child
        .bootstrap_tube
        .send(&slirp_child_startup_args)
        .unwrap();

    let slirp_config = SlirpStartupConfig {
        slirp_pipe: host_pipe,
        shutdown_event: slirp_kill_event
            .try_clone()
            .expect("Failed to clone slirp kill event."),
        #[cfg(feature = "slirp-ring-capture")]
        slirp_capture_file: cfg.slirp_capture_file.take(),
    };
    slirp_child.bootstrap_tube.send(&slirp_config).unwrap();

    let net_child = spawn_net_backend(main_child, children, wait_ctx, cfg)?;

    let net_child_startup_args = CommonChildStartupArgs::new(
        get_log_path(cfg, "net_syslog.log"),
        #[cfg(feature = "crash-report")]
        create_crash_report_attrs(cfg, product_type::SLIRP),
        #[cfg(feature = "process-invariants")]
        process_invariants.clone(),
        Some(metrics_tube_pair(metric_tubes)?),
    )?;
    net_child
        .bootstrap_tube
        .send(&net_child_startup_args)
        .unwrap();

    let net_backend_config = NetBackendConfig {
        guest_pipe,
        slirp_kill_event,
    };
    net_child.bootstrap_tube.send(&net_backend_config).unwrap();
    let exit_event = Event::new().exit_context(Exit::CreateEvent, "failed to create event")?;
    net_child.bootstrap_tube.send(&exit_event).unwrap();
    exit_events.push(exit_event);

    Ok((slirp_child, net_child))
}

fn spawn_slirp(
    children: &mut HashMap<u32, ChildCleanup>,
    wait_ctx: &mut WaitContext<Token>,
    cfg: &mut Config,
) -> Result<ChildProcess> {
    let slirp_child = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["run-slirp"],
        get_log_path(cfg, "slirp_stdout.log"),
        get_log_path(cfg, "slirp_stderr.log"),
        ProcessType::Slirp,
        children,
        wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */ cfg.jail_config.is_some(),
        vec![],
        cfg,
    )?;

    slirp_child
        .tube_transporter
        .serialize_and_transport(slirp_child.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    Ok(slirp_child)
}

fn spawn_net_backend(
    main_child: &mut ChildProcess,
    children: &mut HashMap<u32, ChildCleanup>,
    wait_ctx: &mut WaitContext<Token>,
    cfg: &mut Config,
) -> Result<ChildProcess> {
    let (mut vhost_user_main_tube, mut vhost_user_device_tube) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

    vhost_user_device_tube.set_target_pid(main_child.alias_pid);

    let net_child = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["device", "net"],
        get_log_path(cfg, "net_stdout.log"),
        get_log_path(cfg, "net_stderr.log"),
        ProcessType::Net,
        children,
        wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */ cfg.jail_config.is_some(),
        vec![TubeTransferData {
            tube: vhost_user_device_tube,
            tube_token: TubeToken::VhostUser,
        }],
        cfg,
    )?;

    net_child
        .tube_transporter
        .serialize_and_transport(net_child.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    vhost_user_main_tube.set_target_pid(net_child.alias_pid);
    cfg.net_vhost_user_tube = Some(vhost_user_main_tube);

    Ok(net_child)
}

#[cfg(feature = "gpu")]
/// Create backend and VMM configurations for the GPU device.
fn platform_create_gpu(
    cfg: &Config,
    #[allow(unused_variables)] main_child: &mut ChildProcess,
    exit_events: &mut Vec<Event>,
    exit_evt_wrtube: SendTube,
) -> Result<(GpuBackendConfig, GpuVmmConfig)> {
    let exit_event = Event::new().exit_context(Exit::CreateEvent, "failed to create exit event")?;
    exit_events.push(
        exit_event
            .try_clone()
            .exit_context(Exit::CloneEvent, "failed to clone event")?,
    );

    let mut event_devices = vec![];
    let mut input_event_multi_touch_pipes = vec![];
    let mut input_event_mouse_pipes = vec![];
    let mut input_event_keyboard_pipes = vec![];

    for _ in cfg.virtio_multi_touch.iter() {
        let (event_device_pipe, virtio_input_pipe) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;
        event_devices.push(EventDevice::touchscreen(event_device_pipe));
        input_event_multi_touch_pipes.push(virtio_input_pipe);
    }

    for _ in cfg.virtio_mice.iter() {
        let (event_device_pipe, virtio_input_pipe) =
            StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
                .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;
        event_devices.push(EventDevice::mouse(event_device_pipe));
        input_event_mouse_pipes.push(virtio_input_pipe);
    }

    // One keyboard
    let (event_device_pipe, virtio_input_pipe) =
        StreamChannel::pair(BlockingMode::Nonblocking, FramingMode::Byte)
            .exit_context(Exit::EventDeviceSetup, "failed to set up EventDevice")?;
    event_devices.push(EventDevice::keyboard(event_device_pipe));
    input_event_keyboard_pipes.push(virtio_input_pipe);

    let (backend_config_product, vmm_config_product) =
        get_gpu_product_configs(cfg, main_child.alias_pid)?;

    let backend_config = GpuBackendConfig {
        device_vhost_user_tube: None,
        exit_event,
        exit_evt_wrtube,
        event_devices,
        params: cfg
            .gpu_parameters
            .as_ref()
            .expect("missing GpuParameters in config")
            .clone(),
        product_config: backend_config_product,
    };

    let vmm_config = GpuVmmConfig {
        main_vhost_user_tube: None,
        input_event_multi_touch_pipes,
        input_event_mouse_pipes,
        input_event_keyboard_pipes,
        product_config: vmm_config_product,
    };

    Ok((backend_config, vmm_config))
}

#[cfg(feature = "gpu")]
/// Returns a gpu child process for vhost-user GPU.
fn start_up_gpu(
    cfg: &mut Config,
    gpu_cfg: (GpuBackendConfig, GpuVmmConfig),
    main_child: &mut ChildProcess,
    children: &mut HashMap<u32, ChildCleanup>,
    wait_ctx: &mut WaitContext<Token>,
    metric_tubes: &mut Vec<Tube>,
    #[cfg(feature = "process-invariants")] process_invariants: &EmulatorProcessInvariants,
) -> Result<ChildProcess> {
    let (mut backend_cfg, mut vmm_cfg) = gpu_cfg;

    let (mut main_vhost_user_tube, mut device_host_user_tube) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

    let gpu_child = spawn_child(
        current_exe().unwrap().to_str().unwrap(),
        ["device", "gpu"],
        get_log_path(cfg, "gpu_stdout.log"),
        get_log_path(cfg, "gpu_stderr.log"),
        ProcessType::Gpu,
        children,
        wait_ctx,
        /* skip_bootstrap= */
        #[cfg(test)]
        false,
        /* use_sandbox= */
        cfg.jail_config.is_some(),
        vec![],
        cfg,
    )?;

    gpu_child
        .tube_transporter
        .serialize_and_transport(gpu_child.process_id)
        .exit_context(Exit::TubeTransporterInit, "failed to initialize tube")?;

    // Update target PIDs to new child.
    device_host_user_tube.set_target_pid(main_child.alias_pid);
    main_vhost_user_tube.set_target_pid(gpu_child.alias_pid);

    // Insert vhost-user tube to backend / frontend configs.
    backend_cfg.device_vhost_user_tube = Some(device_host_user_tube);
    vmm_cfg.main_vhost_user_tube = Some(main_vhost_user_tube);

    // Send VMM config to main process. Note we don't set gpu_backend_config, since it is passed to
    // the child.
    cfg.gpu_vmm_config = Some(vmm_cfg);

    let startup_args = CommonChildStartupArgs::new(
        get_log_path(cfg, "gpu_syslog.log"),
        #[cfg(feature = "crash-report")]
        create_crash_report_attrs(cfg, product_type::GPU),
        #[cfg(feature = "process-invariants")]
        process_invariants.clone(),
        Some(metrics_tube_pair(metric_tubes)?),
    )?;
    gpu_child.bootstrap_tube.send(&startup_args).unwrap();

    // Send backend config to GPU child.
    gpu_child.bootstrap_tube.send(&backend_cfg).unwrap();

    Ok(gpu_child)
}

/// Spawns a child process, sending it a control tube as the --bootstrap=HANDLE_NUMBER argument.
/// stdout & stderr are redirected to the provided file paths.
fn spawn_child<I, S>(
    program: &str,
    args: I,
    stdout_path: Option<PathBuf>,
    stderr_path: Option<PathBuf>,
    process_type: ProcessType,
    children: &mut HashMap<u32, ChildCleanup>,
    wait_ctx: &mut WaitContext<Token>,
    #[cfg(test)] skip_bootstrap: bool,
    use_sandbox: bool,
    mut tubes: Vec<TubeTransferData>,
    #[allow(unused_variables)] cfg: &Config,
) -> Result<ChildProcess>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (tube_transport_pipe, tube_transport_main_child) = named_pipes::pair(
        &FramingMode::Message.into(),
        &BlockingMode::Blocking.into(),
        /* timeout= */ 0,
    )
    .exit_context(Exit::CreateSocket, "failed to create socket")?;

    let stdout_file = if let Some(path) = stdout_path {
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path.as_path())
                .with_exit_context(Exit::LogFile, || {
                    format!("failed to open log file {}", path.display())
                })?,
        )
    } else {
        None
    };

    let stderr_file = if let Some(path) = stderr_path {
        Some(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path.as_path())
                .with_exit_context(Exit::LogFile, || {
                    format!("failed to open log file {}", path.display())
                })?,
        )
    } else {
        None
    };

    #[cfg(test)]
    let bootstrap = if !skip_bootstrap {
        vec![
            "--bootstrap".to_string(),
            (tube_transport_main_child.as_raw_descriptor() as usize).to_string(),
        ]
    } else {
        vec![]
    };
    #[cfg(not(test))]
    let bootstrap = vec![
        "--bootstrap".to_string(),
        (tube_transport_main_child.as_raw_descriptor() as usize).to_string(),
    ];

    let input_args: Vec<S> = args.into_iter().collect();
    let args = input_args
        .iter()
        .map(|arg| arg.as_ref())
        .chain(bootstrap.iter().map(|arg| arg.as_ref()));

    #[cfg(feature = "sandbox")]
    let (process_id, child) = if use_sandbox {
        spawn_sandboxed_child(
            program,
            args,
            stdout_file,
            stderr_file,
            vec![&tube_transport_main_child],
            process_policy(process_type, cfg),
        )?
    } else {
        spawn_unsandboxed_child(
            program,
            args,
            stdout_file,
            stderr_file,
            vec![&tube_transport_main_child],
        )?
    };
    #[cfg(not(feature = "sandbox"))]
    let (process_id, child) = spawn_unsandboxed_child(
        program,
        args,
        stdout_file,
        stderr_file,
        vec![&tube_transport_main_child],
    )?;

    let (mut bootstrap_tube, bootstrap_tube_child) =
        Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;

    // Make sure our end of the Tube knows the PID of the child end.
    bootstrap_tube.set_target_pid(process_id);

    tubes.push(TubeTransferData {
        tube: bootstrap_tube_child,
        tube_token: TubeToken::Bootstrap,
    });

    let (dh_tube, dh_tube_child, alias_pid) = if use_sandbox {
        let (broker, child) =
            Tube::pair().exit_context(Exit::CreateTube, "failed to create tube")?;
        (Some(broker), Some(child), rand::random())
    } else {
        (None, None, process_id)
    };

    let tube_transporter =
        TubeTransporter::new(tube_transport_pipe, tubes, Some(alias_pid), dh_tube_child);

    // Register this child to be waited upon.
    let process_handle = Descriptor(child.as_raw_descriptor());
    wait_ctx
        .add(&process_handle, Token::Process(alias_pid))
        .exit_context(
            Exit::WaitContextAdd,
            "failed to add trigger to event context",
        )?;

    children.insert(
        alias_pid,
        ChildCleanup {
            process_type,
            child,
            dh_tube,
        },
    );

    if use_sandbox {
        wait_ctx
            .add(
                children[&alias_pid]
                    .dh_tube
                    .as_ref()
                    .unwrap()
                    .get_read_notifier(),
                Token::DuplicateHandle(alias_pid),
            )
            .exit_context(
                Exit::WaitContextAdd,
                "failed to add trigger to event context",
            )?;
    }

    Ok(ChildProcess {
        bootstrap_tube,
        tube_transporter,
        process_id,
        alias_pid,
    })
}

#[cfg(test)]
mod tests {
    use base::thread::spawn_with_timeout;

    use super::*;

    /// Verifies that the supervisor loop exits normally with a single child that exits.
    #[test]
    fn smoke_test() {
        spawn_with_timeout(|| {
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let exit_events = vec![Event::new().unwrap()];
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "2"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );

            Supervisor::broker_supervise_loop(children, wait_ctx, exit_events).unwrap();
        })
        .try_join(Duration::from_secs(5))
        .unwrap();
    }

    /// Verifies that the supervisor loop exits normally when a device exits first, and then
    /// the main loop exits.
    #[test]
    fn main_and_device_clean_exit() {
        spawn_with_timeout(|| {
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let exit_events = vec![Event::new().unwrap()];
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "4"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );
            let _child_device = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "2"],
                None,
                None,
                ProcessType::Block,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );

            Supervisor::broker_supervise_loop(children, wait_ctx, exit_events).unwrap();
        })
        .try_join(Duration::from_secs(5))
        .unwrap();
    }

    /// Verifies that the supervisor loop ends even if a device takes too long to exit.
    #[test]
    fn device_takes_too_long_to_exit() {
        spawn_with_timeout(|| {
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let exit_events = vec![Event::new().unwrap()];
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "2"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );
            let _child_device = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "11"],
                None,
                None,
                ProcessType::Block,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );

            assert_eq!(
                Supervisor::broker_supervise_loop(children, wait_ctx, exit_events)
                    .to_exit_code()
                    .unwrap(),
                ExitCode::from(Exit::BrokerMainExitedTimeout),
            );
        })
        .try_join(Duration::from_secs(10))
        .unwrap();
    }

    /// Verifies that the supervisor loop ends even if the main process takes too long to exit.
    #[test]
    fn main_takes_too_long_to_exit() {
        spawn_with_timeout(|| {
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let exit_events = vec![Event::new().unwrap()];
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "11"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );
            let _child_device = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "2"],
                None,
                None,
                ProcessType::Block,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );

            assert_eq!(
                Supervisor::broker_supervise_loop(children, wait_ctx, exit_events)
                    .to_exit_code()
                    .unwrap(),
                ExitCode::from(Exit::BrokerDeviceExitedTimeout),
            );
        })
        .try_join(Duration::from_secs(10))
        .unwrap();
    }

    /// Verifies that the supervisor loop ends even if a device takes too long to exit.
    #[test]
    fn device_crash_returns_child_error() {
        spawn_with_timeout(|| {
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let exit_events = vec![Event::new().unwrap()];
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "2"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );
            let _child_device = spawn_child(
                "cmd",
                ["/c", "exit -1"],
                None,
                None,
                ProcessType::Block,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );

            assert_eq!(
                Supervisor::broker_supervise_loop(children, wait_ctx, exit_events)
                    .to_exit_code()
                    .unwrap(),
                (to_process_type_error(-1i32 as u32, ProcessType::Block) as i32),
            );
        })
        .try_join(Duration::from_secs(10))
        .unwrap();
    }

    /// Verifies that sigterm makes the supervisor loop signal the exit event.
    #[test]
    fn sigterm_signals_exit_event() {
        let exit_event = Event::new().unwrap();
        let exit_event_copy = exit_event.try_clone().unwrap();

        spawn_with_timeout(move || {
            let sigterm_event = Event::new().unwrap();
            let mut wait_ctx: WaitContext<Token> = WaitContext::new().unwrap();
            let mut children: HashMap<u32, ChildCleanup> = HashMap::new();
            let _child_main = spawn_child(
                "ping",
                ["127.0.0.1", "-n", "3"],
                None,
                None,
                ProcessType::Main,
                &mut children,
                &mut wait_ctx,
                /* skip_bootstrap= */ true,
                /* use_sandbox= */ false,
                Vec::new(),
                &Config::default(),
            );
            wait_ctx.add(&sigterm_event, Token::Sigterm).unwrap();
            sigterm_event.signal().unwrap();

            assert_eq!(
                Supervisor::broker_supervise_loop(children, wait_ctx, vec![exit_event_copy])
                    .to_exit_code()
                    .unwrap(),
                ExitCode::from(Exit::KilledBySignal),
            );
        })
        .try_join(Duration::from_secs(10))
        .unwrap();

        exit_event.wait_timeout(Duration::from_secs(0)).unwrap();
    }
}

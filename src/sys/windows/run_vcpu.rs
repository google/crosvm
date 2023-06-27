// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::__cpuid;
use std::arch::x86_64::__cpuid_count;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use arch::CpuConfigArch;
use arch::CpuSet;
use arch::IrqChipArch;
use arch::LinuxArch;
use arch::RunnableLinuxVm;
use arch::VcpuAffinity;
use arch::VcpuArch;
use arch::VmArch;
use base::error;
use base::info;
use base::set_audio_thread_priority;
use base::set_cpu_affinity;
use base::warn;
use base::Event;
use base::Result as BaseResult;
use base::SafeMultimediaHandle;
use base::SendTube;
use base::Timer;
use base::Tube;
use base::VmEventType;
use cros_async::select2;
use cros_async::EventAsync;
use cros_async::Executor;
use cros_async::SelectResult;
use cros_async::TimerAsync;
use cros_tracing::trace_event;
use crosvm_cli::bail_exit_code;
use crosvm_cli::sys::windows::exit::Exit;
use crosvm_cli::sys::windows::exit::ExitContext;
use crosvm_cli::sys::windows::exit::ExitContextAnyhow;
use devices::tsc::TscSyncMitigations;
use devices::Bus;
use devices::VcpuRunState;
use futures::pin_mut;
#[cfg(feature = "whpx")]
use hypervisor::whpx::WhpxVcpu;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use hypervisor::CpuConfigX86_64;
use hypervisor::HypervisorCap;
use hypervisor::IoEventAddress;
use hypervisor::IoOperation;
use hypervisor::IoParams;
use hypervisor::VcpuExit;
use hypervisor::VcpuInitX86_64;
use sync::Condvar;
use sync::Mutex;
use vm_control::VcpuControl;
use vm_control::VmRunMode;
use winapi::shared::winerror::ERROR_RETRY;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::cpuid::adjust_cpuid;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::cpuid::CpuIdContext;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86_64::X8664arch as Arch;

#[cfg(feature = "stats")]
use crate::crosvm::sys::windows::stats::StatisticsCollector;
#[cfg(feature = "stats")]
use crate::crosvm::sys::windows::stats::VmExitStatistics;
use crate::sys::windows::save_vcpu_tsc_offset;
use crate::sys::windows::ExitState;

const ERROR_RETRY_I32: i32 = ERROR_RETRY as i32;

#[derive(Default)]
pub struct VcpuRunMode {
    mtx: Mutex<VmRunMode>,
    cvar: Condvar,
}

impl VcpuRunMode {
    pub fn get_mode(&self) -> VmRunMode {
        *self.mtx.lock()
    }

    pub fn set_and_notify(&self, new_mode: VmRunMode) {
        *self.mtx.lock() = new_mode;
        self.cvar.notify_all();
    }
}

struct RunnableVcpuInfo<V> {
    vcpu: V,
    thread_priority_handle: Option<SafeMultimediaHandle>,
}

#[derive(Clone, Debug)]
struct VcpuMonitoringMetadata {
    pub start_instant: Instant,
    // Milliseconds since the baseline start_instant
    pub last_run_time: Arc<AtomicU64>,
    pub last_exit_snapshot: Arc<Mutex<Option<VcpuExitData>>>,
}

#[derive(Clone, Debug)]
struct VcpuRunThread {
    pub cpu_id: usize,
    pub monitoring_metadata: Option<VcpuMonitoringMetadata>,
}

impl VcpuRunThread {
    pub fn new(cpu_id: usize, enable_vcpu_monitoring: bool) -> VcpuRunThread {
        VcpuRunThread {
            cpu_id,
            monitoring_metadata: enable_vcpu_monitoring.then(|| VcpuMonitoringMetadata {
                start_instant: Instant::now(),
                last_run_time: Arc::new(AtomicU64::new(0)),
                last_exit_snapshot: Arc::new(Mutex::new(Option::None)),
            }),
        }
    }

    /// Perform WHPX-specific vcpu configurations
    #[cfg(feature = "whpx")]
    fn whpx_configure_vcpu(vcpu: &mut dyn VcpuArch, irq_chip: &mut dyn IrqChipArch) {
        // only apply to actual WhpxVcpu instances
        if let Some(whpx_vcpu) = vcpu.downcast_mut::<WhpxVcpu>() {
            // WhpxVcpu instances need to know the TSC and Lapic frequencies to handle Hyper-V MSR reads
            // and writes.
            let tsc_freq = devices::tsc::tsc_frequency()
                .map_err(|e| {
                    error!(
                        "Could not determine TSC frequency, WHPX vcpu will not be configured with \
                        a TSC Frequency: {e}"
                    );
                    e
                })
                .ok();
            whpx_vcpu.set_frequencies(tsc_freq, irq_chip.lapic_frequency());
        }
    }

    // Sets up a vcpu and converts it into a runnable vcpu.
    fn runnable_vcpu<V>(
        cpu_id: usize,
        vcpu: Option<V>,
        vcpu_init: VcpuInitX86_64,
        vm: &impl VmArch,
        irq_chip: &mut dyn IrqChipArch,
        vcpu_count: usize,
        run_rt: bool,
        vcpu_affinity: Option<CpuSet>,
        no_smt: bool,
        has_bios: bool,
        host_cpu_topology: bool,
        force_calibrated_tsc_leaf: bool,
    ) -> Result<RunnableVcpuInfo<V>>
    where
        V: VcpuArch,
    {
        let mut vcpu = match vcpu {
            Some(v) => v,
            None => {
                // If vcpu is None, it means this arch/hypervisor requires create_vcpu to be called from
                // the vcpu thread.
                match vm
                    .create_vcpu(cpu_id)
                    .exit_context(Exit::CreateVcpu, "failed to create vcpu")?
                    .downcast::<V>()
                {
                    Ok(v) => *v,
                    Err(_) => panic!("VM created wrong type of VCPU"),
                }
            }
        };

        irq_chip
            .add_vcpu(cpu_id, &vcpu)
            .exit_context(Exit::AddIrqChipVcpu, "failed to add vcpu to irq chip")?;

        if let Some(affinity) = vcpu_affinity {
            if let Err(e) = set_cpu_affinity(affinity) {
                error!("Failed to set CPU affinity: {}", e);
            }
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let cpu_config = Some(CpuConfigX86_64::new(
            force_calibrated_tsc_leaf,
            host_cpu_topology,
            false, /* enable_hwp */
            false, /* enable_pnp_data */
            no_smt,
            false, /* itmt */
            None,  /* hybrid_type */
        ));

        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let cpu_config = None;

        Arch::configure_vcpu(
            vm,
            vm.get_hypervisor(),
            irq_chip,
            &mut vcpu,
            vcpu_init,
            cpu_id,
            vcpu_count,
            has_bios,
            cpu_config,
        )
        .exit_context(Exit::ConfigureVcpu, "failed to configure vcpu")?;

        #[cfg(feature = "whpx")]
        Self::whpx_configure_vcpu(&mut vcpu, irq_chip);

        let mut thread_priority_handle = None;
        if run_rt {
            // Until we are multi process on Windows, we can't use the normal thread priority APIs;
            // instead, we use a trick from the audio device which is able to set a thread RT even
            // though the process itself is not RT.
            thread_priority_handle = match set_audio_thread_priority() {
                Ok(hndl) => Some(hndl),
                Err(e) => {
                    warn!("Failed to set vcpu thread to real time priority: {}", e);
                    None
                }
            };
        }

        Ok(RunnableVcpuInfo {
            vcpu,
            thread_priority_handle,
        })
    }

    pub fn run<V>(
        &self,
        vcpu: Option<V>,
        vcpu_init: VcpuInitX86_64,
        vcpus: Arc<Mutex<Vec<Box<dyn VcpuArch>>>>,
        vm: impl VmArch + 'static,
        mut irq_chip: Box<dyn IrqChipArch + 'static>,
        vcpu_count: usize,
        run_rt: bool,
        vcpu_affinity: Option<CpuSet>,
        delay_rt: bool,
        no_smt: bool,
        start_barrier: Arc<Barrier>,
        vcpu_create_barrier: Arc<Barrier>,
        has_bios: bool,
        mut io_bus: devices::Bus,
        mut mmio_bus: devices::Bus,
        vm_evt_wrtube: SendTube,
        run_mode_arc: Arc<VcpuRunMode>,
        #[cfg(feature = "stats")] stats: Option<Arc<Mutex<StatisticsCollector>>>,
        host_cpu_topology: bool,
        tsc_offset: Option<u64>,
        force_calibrated_tsc_leaf: bool,
        vcpu_control: mpsc::Receiver<VcpuControl>,
    ) -> Result<JoinHandle<Result<()>>>
    where
        V: VcpuArch + 'static,
    {
        let context = self.clone();
        thread::Builder::new()
            .name(format!("crosvm_vcpu{}", self.cpu_id))
            .spawn(move || {
                // Having a closure returning ExitState guarentees that we
                // send a VmEventType on all code paths after the closure
                // returns.
                let vcpu_fn = || -> Result<ExitState> {
                    let runnable_vcpu = Self::runnable_vcpu(
                        context.cpu_id,
                        vcpu,
                        vcpu_init,
                        &vm,
                        irq_chip.as_mut(),
                        vcpu_count,
                        run_rt && !delay_rt,
                        vcpu_affinity,
                        no_smt,
                        has_bios,
                        host_cpu_topology,
                        force_calibrated_tsc_leaf,
                    );

                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    let cpu_config = CpuConfigX86_64::new(
                        force_calibrated_tsc_leaf,
                        host_cpu_topology,
                        false, /* enable_hwp */
                        false, /* enable_pnp_data */
                        no_smt,
                        false, /* itmt */
                        None,  /* hybrid_type */
                    );

                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    let cpuid_context = CpuIdContext::new(
                        context.cpu_id,
                        vcpu_count,
                        Some(irq_chip.as_ref()),
                        cpu_config,
                        vm.get_hypervisor()
                            .check_capability(HypervisorCap::CalibratedTscLeafRequired),
                        __cpuid_count,
                        __cpuid,
                    );

                    // The vcpu_create_barrier is supplied from the main thread in order for it to
                    // wait until this thread is done creating its vcpu.
                    vcpu_create_barrier.wait();

                    // Wait for this barrier before continuing forward.
                    start_barrier.wait();

                    let RunnableVcpuInfo {
                        vcpu,
                        thread_priority_handle: _thread_priority_handle,
                    } = runnable_vcpu?;

                    if let Some(offset) = tsc_offset {
                        vcpu.set_tsc_offset(offset).unwrap_or_else(|e| {
                            error!(
                                "Failed to set tsc_offset of {} on vcpu {}: {}",
                                offset, context.cpu_id, e
                            )
                        });
                    }

                    // Clone vcpu so it can be used by the main thread to force a vcpu run to exit
                    vcpus
                        .lock()
                        .push(Box::new(vcpu.try_clone().expect("Could not clone vcpu!")));

                    mmio_bus.set_access_id(context.cpu_id);
                    io_bus.set_access_id(context.cpu_id);

                    vcpu_loop(
                        &context,
                        vcpu,
                        vm,
                        irq_chip,
                        io_bus,
                        mmio_bus,
                        run_mode_arc,
                        #[cfg(feature = "stats")]
                        stats,
                        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                        cpuid_context,
                        vcpu_control,
                    )
                };

                let final_event_data = match vcpu_fn().unwrap_or_else(|e| {
                    error!(
                        "vcpu {} run loop exited with error: {:#}",
                        context.cpu_id, e
                    );
                    ExitState::Stop
                }) {
                    ExitState::Stop => VmEventType::Exit,
                    _ => unreachable!(),
                };
                vm_evt_wrtube
                    .send::<VmEventType>(&final_event_data)
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to send final event {:?} on vcpu {}: {}",
                            final_event_data, context.cpu_id, e
                        )
                    });
                Ok(())
            })
            .exit_context(Exit::SpawnVcpu, "failed to spawn VCPU thread")
    }
}

#[derive(Clone, Debug)]
struct VcpuExitData {
    // Represented by duration since baseline start_instant
    exit_time: Duration,
    exit_result: BaseResult<VcpuExit>,
}

impl Display for VcpuExitData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exit result: {:?}", self.exit_result)
    }
}

struct VcpuStallMonitor {
    vcpu_run_threads: Vec<VcpuRunThread>,
    run_mode: Arc<VcpuRunMode>,
}

impl VcpuStallMonitor {
    const HOST_STALL_TIMEOUT: Duration = Duration::from_secs(2);
    const VCPU_CHECKUP_INTERVAL: Duration = Duration::from_secs(1);
    const STALL_REPORTING_LIMITER: Duration = Duration::from_secs(10);

    pub fn init(run_mode: Arc<VcpuRunMode>) -> VcpuStallMonitor {
        VcpuStallMonitor {
            vcpu_run_threads: vec![],
            run_mode,
        }
    }

    pub fn add_vcpu_thread(&mut self, thread: VcpuRunThread) {
        self.vcpu_run_threads.push(thread);
    }

    pub fn run(self, exit_event: &Event) -> Result<JoinHandle<Result<()>>> {
        let cloned_exit_event = exit_event
            .try_clone()
            .exit_context(Exit::CloneEvent, "failed to clone event")?;
        thread::Builder::new()
            .name("crosvm_vcpu_stall_monitor".to_string())
            .spawn(move || {
                let ex = Executor::new()?;

                let mut timer = TimerAsync::new(Timer::new()?, &ex)?;
                let mut reset_timer = true;

                let exit_evt_async = EventAsync::new(cloned_exit_event, &ex)?;
                let exit_future = exit_evt_async.next_val();
                pin_mut!(exit_future);
                'main: loop {
                    if reset_timer {
                        timer.reset(
                            Self::VCPU_CHECKUP_INTERVAL,
                            Some(Self::VCPU_CHECKUP_INTERVAL),
                        )?;
                        reset_timer = false;
                    }
                    let timer_future = timer.wait();
                    pin_mut!(timer_future);
                    match ex.run_until(select2(timer_future, exit_future)) {
                        Ok((timer_result, exit_result)) => {
                            match exit_result {
                                SelectResult::Finished(_) => {
                                    info!("vcpu monitor got exit event");
                                    break 'main;
                                }
                                SelectResult::Pending(future) => exit_future = future,
                            }

                            match timer_result {
                                SelectResult::Finished(Err(e)) => {
                                    error!(
                                        "vcpu monitor aborting due to error awaiting future: {}",
                                        e
                                    );
                                    break 'main;
                                }
                                SelectResult::Finished(_) => self.report_any_stalls(),
                                _ => (),
                            }
                        }
                        Err(e) => {
                            error!("vcpu monitor failed to wait on future set: {:?}", e);
                            break 'main;
                        }
                    }

                    // Always ensure the vcpus aren't suspended before continuing to montior.
                    let mut run_mode_lock = self.run_mode.mtx.lock();
                    loop {
                        match *run_mode_lock {
                            VmRunMode::Running => break,
                            VmRunMode::Suspending | VmRunMode::Breakpoint => {
                                info!("vcpu monitor pausing until end of suspension");
                                run_mode_lock = self.run_mode.cvar.wait(run_mode_lock);
                                reset_timer = true;
                            }
                            VmRunMode::Exiting => {
                                info!("vcpu monitor detected vm exit");
                                break 'main;
                            }
                        }
                    }
                }

                Ok(())
            })
            .exit_context(
                Exit::SpawnVcpuMonitor,
                "failed to spawn VCPU stall monitor thread",
            )
    }

    fn report_any_stalls(&self) {
        // TODO(b/208267651): Add and fire Clearcut events for stalls (and add tests)
        // TODO(b/208267651): Also test guest stalls (vcpu.run() goes too long without exiting)
        let now = Instant::now();
        for vcpu_thread in self.vcpu_run_threads.iter() {
            let monitoring_metadata = vcpu_thread.monitoring_metadata.as_ref().unwrap();
            if let Some(ref exit_snapshot) = monitoring_metadata.last_exit_snapshot.lock().clone() {
                let last_run =
                    Duration::from_millis(monitoring_metadata.last_run_time.load(Ordering::SeqCst));
                if last_run < exit_snapshot.exit_time {
                    // VCPU is between runs
                    let time_since_exit = now.saturating_duration_since(
                        monitoring_metadata.start_instant + exit_snapshot.exit_time,
                    );
                    if time_since_exit > Self::HOST_STALL_TIMEOUT {
                        self.report_stall(vcpu_thread.cpu_id, exit_snapshot, time_since_exit);
                    }
                }
            };
        }
    }

    fn report_stall(&self, cpu_id: usize, exit_data: &VcpuExitData, stall_time: Duration) {
        if stall_time > Self::STALL_REPORTING_LIMITER {
            return;
        }
        // Double check the Vm is running. We don't care about stalls during suspension/exit
        if *self.run_mode.mtx.lock() != VmRunMode::Running {
            let duration_string = format!("{:.1}sec", stall_time.as_secs_f32());
            error!(
                "Host stall for {} on VCPU {} exit while handling: {}",
                duration_string, cpu_id, exit_data,
            );
        }
    }
}

fn setup_vcpu_signal_handler() -> Result<()> {
    Ok(())
}

pub fn run_all_vcpus<V: VmArch + 'static, Vcpu: VcpuArch + 'static>(
    vcpus: Vec<Option<Vcpu>>,
    vcpu_boxes: Arc<Mutex<Vec<Box<dyn VcpuArch>>>>,
    guest_os: &RunnableLinuxVm<V, Vcpu>,
    exit_evt: &Event,
    vm_evt_wrtube: &SendTube,
    #[cfg(feature = "stats")] stats: &Option<Arc<Mutex<StatisticsCollector>>>,
    host_cpu_topology: bool,
    run_mode_arc: Arc<VcpuRunMode>,
    tsc_sync_mitigations: TscSyncMitigations,
    force_calibrated_tsc_leaf: bool,
) -> Result<(Vec<JoinHandle<Result<()>>>, Vec<mpsc::Sender<VcpuControl>>)> {
    let mut vcpu_threads = Vec::with_capacity(guest_os.vcpu_count + 1);
    let mut vcpu_control_channels = Vec::with_capacity(guest_os.vcpu_count);
    let start_barrier = Arc::new(Barrier::new(guest_os.vcpu_count + 1));
    let enable_vcpu_monitoring = anti_tamper::enable_vcpu_monitoring();
    setup_vcpu_signal_handler()?;

    let mut stall_monitor =
        enable_vcpu_monitoring.then(|| VcpuStallMonitor::init(run_mode_arc.clone()));
    for (cpu_id, vcpu) in vcpus.into_iter().enumerate() {
        let vcpu_affinity = match guest_os.vcpu_affinity.clone() {
            Some(VcpuAffinity::Global(v)) => Some(v),
            Some(VcpuAffinity::PerVcpu(mut m)) => Some(m.remove(&cpu_id).unwrap_or_default()),
            None => None,
        };

        // TSC sync mitigations may set vcpu affinity and set a TSC offset
        let (vcpu_affinity, tsc_offset): (Option<CpuSet>, Option<u64>) =
            if let Some(mitigation_affinity) = tsc_sync_mitigations.get_vcpu_affinity(cpu_id) {
                if vcpu_affinity.is_none() {
                    (
                        Some(CpuSet::new(mitigation_affinity)),
                        tsc_sync_mitigations.get_vcpu_tsc_offset(cpu_id),
                    )
                } else {
                    error!(
                        "Core affinity {:?} specified via commandline conflicts and overrides \
                        affinity needed for TSC sync mitigation: {:?}.",
                        vcpu_affinity, mitigation_affinity
                    );
                    (vcpu_affinity, None)
                }
            } else {
                (vcpu_affinity, None)
            };

        let vcpu_init = &guest_os.vcpu_init[cpu_id];
        // The vcpu_create_barrier allows the main thread to delay the spawning of additional
        // vcpu threads until a single vcpu thread spawned has finished creating it's vcpu.
        // We currently use this to allow creation of 1 vcpu at a time for all hypervisors.
        // There are issues with multiple hypervisors with this approach:
        // - Windows 11 has a regression which causes a BSOD with creation of multiple vcpu
        //   in parallel. http://b/229635845 for more details.
        // - GHAXM/HAXM cannot create vcpu0 in parallel with other Vcpus.
        let vcpu_create_barrier = Arc::new(Barrier::new(2));
        let vcpu_run_thread = VcpuRunThread::new(cpu_id, enable_vcpu_monitoring);
        let (vcpu_control_send, vcpu_control_recv) = mpsc::channel();
        vcpu_control_channels.push(vcpu_control_send);
        let join_handle = vcpu_run_thread.run(
            vcpu,
            vcpu_init.clone(),
            vcpu_boxes.clone(),
            guest_os
                .vm
                .try_clone()
                .exit_context(Exit::CloneEvent, "failed to clone vm")?,
            guest_os
                .irq_chip
                .try_box_clone()
                .exit_context(Exit::CloneEvent, "failed to clone event")?,
            guest_os.vcpu_count,
            guest_os.rt_cpus.contains(&cpu_id),
            vcpu_affinity,
            guest_os.delay_rt,
            guest_os.no_smt,
            start_barrier.clone(),
            vcpu_create_barrier.clone(),
            guest_os.has_bios,
            (*guest_os.io_bus).clone(),
            (*guest_os.mmio_bus).clone(),
            vm_evt_wrtube
                .try_clone()
                .exit_context(Exit::CloneTube, "failed to clone tube")?,
            run_mode_arc.clone(),
            #[cfg(feature = "stats")]
            stats.clone(),
            host_cpu_topology,
            tsc_offset,
            force_calibrated_tsc_leaf,
            vcpu_control_recv,
        )?;
        if let Some(ref mut monitor) = stall_monitor {
            monitor.add_vcpu_thread(vcpu_run_thread);
        }

        // Wait until the vcpu is created before we start a new vcpu thread
        vcpu_create_barrier.wait();

        vcpu_threads.push(join_handle);
    }
    if let Some(monitor) = stall_monitor {
        vcpu_threads.push(monitor.run(exit_evt)?);
    }
    // Now wait on the start barrier to start all threads at the same time.
    start_barrier.wait();
    Ok((vcpu_threads, vcpu_control_channels))
}

fn vcpu_loop<V>(
    context: &VcpuRunThread,
    mut vcpu: V,
    vm: impl VmArch + 'static,
    irq_chip: Box<dyn IrqChipArch + 'static>,
    io_bus: Bus,
    mmio_bus: Bus,
    run_mode_arc: Arc<VcpuRunMode>,
    #[cfg(feature = "stats")] stats: Option<Arc<Mutex<StatisticsCollector>>>,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] cpuid_context: CpuIdContext,
    vcpu_control: mpsc::Receiver<VcpuControl>,
) -> Result<ExitState>
where
    V: VcpuArch + 'static,
{
    #[cfg(feature = "stats")]
    let mut exit_stats = VmExitStatistics::new();

    #[cfg(feature = "stats")]
    {
        mmio_bus.stats.lock().set_enabled(stats.is_some());
        io_bus.stats.lock().set_enabled(stats.is_some());
        exit_stats.set_enabled(stats.is_some());
    }

    let mut save_tsc_offset = true;

    loop {
        let _trace_event = trace_event!(crosvm, "vcpu loop");
        let mut check_vm_shutdown = false;

        match irq_chip.wait_until_runnable(&vcpu).with_exit_context(
            Exit::WaitUntilRunnable,
            || {
                format!(
                    "error waiting for vcpu {} to become runnable",
                    context.cpu_id
                )
            },
        )? {
            VcpuRunState::Runnable => {}
            VcpuRunState::Interrupted => check_vm_shutdown = true,
        }

        if !check_vm_shutdown {
            let exit = {
                let _trace_event = trace_event!(crosvm, "vcpu::run");
                if let Some(ref monitoring_metadata) = context.monitoring_metadata {
                    monitoring_metadata.last_run_time.store(
                        // Safe conversion because millis will always be < u32::MAX
                        monitoring_metadata
                            .start_instant
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .unwrap(),
                        Ordering::SeqCst,
                    );
                }
                vcpu.run()
            };
            if let Some(ref monitoring_metadata) = context.monitoring_metadata {
                *monitoring_metadata.last_exit_snapshot.lock() = Some(VcpuExitData {
                    exit_time: monitoring_metadata.start_instant.elapsed(),
                    exit_result: exit,
                });
            }

            // save the tsc offset if we need to
            if save_tsc_offset {
                if let Ok(offset) = vcpu.get_tsc_offset() {
                    save_vcpu_tsc_offset(offset, context.cpu_id);
                } else {
                    error!("Unable to determine TSC offset");
                }
                save_tsc_offset = false;
            }

            #[cfg(feature = "stats")]
            let start = exit_stats.start_stat();

            match exit {
                Ok(VcpuExit::Io) => {
                    let _trace_event = trace_event!(crosvm, "VcpuExit::Io");
                    vcpu.handle_io(&mut |IoParams { address, mut size, operation}| {
                        match operation {
                            IoOperation::Read => {
                                let mut data = [0u8; 8];
                                if size > data.len() {
                                    error!("unsupported IoIn size of {} bytes", size);
                                    size = data.len();
                                }
                                io_bus.read(address, &mut data[..size]);
                                Some(data)
                            }
                            IoOperation::Write { data } => {
                                if size > data.len() {
                                    error!("unsupported IoOut size of {} bytes", size);
                                    size = data.len()
                                }
                                vm.handle_io_events(IoEventAddress::Pio(address), &data[..size])
                                    .unwrap_or_else(|e| error!(
                                        "failed to handle ioevent for pio write to {} on vcpu {}: {}",
                                        address, context.cpu_id, e
                                    ));
                                io_bus.write(address, &data[..size]);
                                None
                            }
                        }
                    }).unwrap_or_else(|e| error!("failed to handle io: {}", e));
                }
                Ok(VcpuExit::Mmio) => {
                    let _trace_event = trace_event!(crosvm, "VcpuExit::Mmio");
                    vcpu.handle_mmio(&mut |IoParams { address, mut size, operation }| {
                        match operation {
                            IoOperation::Read => {
                                let mut data = [0u8; 8];
                                if size > data.len() {
                                    error!("unsupported MmioRead size of {} bytes", size);
                                    size = data.len();
                                }
                                {
                                    let data = &mut data[..size];
                                    if !mmio_bus.read(address, data) {
                                        info!(
                                            "mmio read failed: {:x}; trying memory read..",
                                            address
                                        );
                                        vm.get_memory()
                                            .read_exact_at_addr(
                                                data,
                                                vm_memory::GuestAddress(address),
                                            )
                                            .unwrap_or_else(|e| {
                                                error!(
                                                    "guest memory read failed at {:x}: {}",
                                                    address, e
                                                )
                                            });
                                    }
                                }
                                Some(data)
                            }
                            IoOperation::Write { data } => {
                                if size > data.len() {
                                    error!("unsupported MmioWrite size of {} bytes", size);
                                    size = data.len()
                                }
                                let data = &data[..size];
                                vm.handle_io_events(IoEventAddress::Mmio(address), data)
                                    .unwrap_or_else(|e| error!(
                                        "failed to handle ioevent for mmio write to {} on vcpu {}: {}",
                                        address, context.cpu_id, e
                                    ));
                                if !mmio_bus.write(address, data) {
                                    info!(
                                        "mmio write failed: {:x}; trying memory write..",
                                        address
                                    );
                                    vm.get_memory()
                                        .write_all_at_addr(data, vm_memory::GuestAddress(address))
                                        .unwrap_or_else(|e| error!(
                                            "guest memory write failed at {:x}: {}",
                                            address, e
                                        ));
                                }
                                None
                            }
                        }
                    }).unwrap_or_else(|e| error!("failed to handle mmio: {}", e));
                }
                Ok(VcpuExit::IoapicEoi { vector }) => {
                    irq_chip.broadcast_eoi(vector).unwrap_or_else(|e| {
                        error!(
                            "failed to broadcast eoi {} on vcpu {}: {}",
                            vector, context.cpu_id, e
                        )
                    });
                }
                Ok(VcpuExit::IrqWindowOpen) => {}
                Ok(VcpuExit::Hlt) => irq_chip.halted(context.cpu_id),

                // VcpuExit::Shutdown is always an error on Windows.  HAXM exits with
                // Shutdown only for triple faults and other vcpu panics.  WHPX never exits
                // with Shutdown.  Normal reboots and shutdowns, like window close, use
                // the vm event tube and VmRunMode::Exiting instead of VcpuExit::Shutdown.
                Ok(VcpuExit::Shutdown) => bail_exit_code!(Exit::VcpuShutdown, "vcpu shutdown"),
                Ok(VcpuExit::FailEntry {
                    hardware_entry_failure_reason,
                }) => bail_exit_code!(
                    Exit::VcpuFailEntry,
                    "vcpu hw run failure: {:#x}",
                    hardware_entry_failure_reason,
                ),
                Ok(VcpuExit::SystemEventShutdown) => {
                    bail_exit_code!(Exit::VcpuSystemEvent, "vcpu SystemEventShutdown")
                }
                Ok(VcpuExit::SystemEventReset) => {
                    bail_exit_code!(Exit::VcpuSystemEvent, "vcpu SystemEventReset")
                }
                Ok(VcpuExit::SystemEventCrash) => {
                    bail_exit_code!(Exit::VcpuSystemEvent, "vcpu SystemEventCrash")
                }

                // When we're shutting down (e.g., emulator window gets closed), GVM vmexits
                // with KVM_EXIT_INTR, which vcpu.run maps to VcpuExit::Intr.  But KVM_EXIT_INTR
                // can happen during normal operation too, when GVM's timer finds requests
                // pending from the host.  So we set check_vm_shutdown, then below check the
                // VmRunMode state to see if we should exit the run loop.
                Ok(VcpuExit::Intr) => check_vm_shutdown = true,
                Ok(VcpuExit::Canceled) => check_vm_shutdown = true,
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Ok(VcpuExit::Cpuid { mut entry }) => {
                    let _trace_event = trace_event!(crosvm, "VcpuExit::Cpuid");
                    // adjust the results based on crosvm logic
                    adjust_cpuid(&mut entry, &cpuid_context);

                    // let the vcpu finish handling the exit
                    vcpu.handle_cpuid(&entry).unwrap_or_else(|e| {
                        error!(
                            "failed to handle setting cpuid results on cpu {}: {}",
                            context.cpu_id, e
                        )
                    });
                }
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                Ok(VcpuExit::MsrAccess) => {} // MsrAccess handled by hypervisor impl
                Ok(r) => {
                    error!("unexpected vcpu.run return value: {:?}", r);
                    check_vm_shutdown = true;
                }
                Err(e) => match e.errno() {
                    ERROR_RETRY_I32 => {}
                    _ => {
                        run_mode_arc.set_and_notify(VmRunMode::Exiting);
                        Err(e).exit_context(Exit::VcpuRunError, "vcpu run error")?;
                    }
                },
            }

            #[cfg(feature = "stats")]
            exit_stats.end_stat(&exit, start);
        }

        if check_vm_shutdown {
            let mut run_mode_lock = run_mode_arc.mtx.lock();
            loop {
                match *run_mode_lock {
                    VmRunMode::Running => {
                        process_vcpu_control_messages(&mut vcpu, *run_mode_lock, &vcpu_control);
                        break;
                    }
                    VmRunMode::Suspending => {
                        if let Err(e) = vcpu.on_suspend() {
                            error!(
                                "failed to signal to hypervisor that vcpu {} is being suspended: {}",
                                context.cpu_id, e
                            );
                        }
                    }
                    VmRunMode::Breakpoint => {}
                    VmRunMode::Exiting => {
                        #[cfg(feature = "stats")]
                        if let Some(stats) = stats {
                            let mut collector = stats.lock();
                            collector.pio_bus_stats.push(io_bus.stats);
                            collector.mmio_bus_stats.push(mmio_bus.stats);
                            collector.vm_exit_stats.push(exit_stats);
                        }
                        return Ok(ExitState::Stop);
                    }
                }

                // For non running modes, we don't want to process messages until we've completed
                // *all* work for any VmRunMode transition. This is because one control message
                // asks us to inform the requestor of our current state. We want to make sure our
                // our state has completely transitioned before we respond to the requestor. If
                // we do this elsewhere, we might respond while in a partial state which could
                // break features like snapshotting (e.g. by introducing a race condition).
                process_vcpu_control_messages(&mut vcpu, *run_mode_lock, &vcpu_control);

                // Give ownership of our exclusive lock to the condition variable that
                // will block. When the condition variable is notified, `wait` will
                // unblock and return a new exclusive lock.
                run_mode_lock = run_mode_arc.cvar.wait(run_mode_lock);
            }
        }

        irq_chip.inject_interrupts(&vcpu).unwrap_or_else(|e| {
            error!(
                "failed to inject interrupts for vcpu {}: {}",
                context.cpu_id, e
            )
        });
    }
}

fn process_vcpu_control_messages<V>(
    vcpu: &mut V,
    run_mode: VmRunMode,
    vcpu_control: &mpsc::Receiver<VcpuControl>,
) where
    V: VcpuArch + 'static,
{
    let control_messages: Vec<VcpuControl> = vcpu_control.try_iter().collect();

    for msg in control_messages {
        match msg {
            VcpuControl::RunState(new_mode) => {
                panic!("VCPUs do not handle RunState messages on Windows")
            }
            #[cfg(feature = "gdb")]
            VcpuControl::Debug(d) => {
                unimplemented!("Windows VCPUs do not support debug yet.");
            }
            VcpuControl::MakeRT => {
                unimplemented!("Windows VCPUs do not support on demand RT.");
            }
            VcpuControl::GetStates(response_chan) => {
                // Wondering why we need this given that the state value is already in an Arc?
                //
                // The control loop generally sets the run mode directly via the Arc; however,
                // it has no way of knowing *when* the VCPU threads have actually acknowledged
                // the new value. By returning the value in here, we prove the the control loop
                // we have accepted the new value and are done with our state change.
                if let Err(e) = response_chan.send(run_mode) {
                    error!("Failed to send GetState: {}", e);
                };
            }
            VcpuControl::Snapshot(response_chan) => {
                let resp = vcpu
                    .snapshot()
                    .with_context(|| format!("Failed to snapshot Vcpu #{}", vcpu.id()));
                if let Err(e) = response_chan.send(resp) {
                    error!("Failed to send snapshot response: {}", e);
                }
            }
            VcpuControl::Restore(response_chan, vcpu_data) => {
                let resp = vcpu
                    .restore(&vcpu_data)
                    .with_context(|| format!("Failed to restore Vcpu #{}", vcpu.id()));
                if let Err(e) = response_chan.send(resp) {
                    error!("Failed to send restore response: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SetupData {
        pub monitor: VcpuStallMonitor,
        pub exit_evt: Event,
    }

    fn set_up_stall_monitor(vcpu_count: usize) -> Result<SetupData> {
        let run_mode = Arc::new(VcpuRunMode::default());
        let mut monitor = VcpuStallMonitor::init(run_mode);

        for id in 0..vcpu_count {
            let new_vcpu = VcpuRunThread::new(id, true /* enable_vcpu_monitoring */);
            monitor.add_vcpu_thread(new_vcpu);
        }

        Ok(SetupData {
            monitor,
            exit_evt: Event::new().expect("Failed to create event"),
        })
    }

    #[test]
    fn stall_monitor_closes_on_exit_evt() -> Result<()> {
        let SetupData { monitor, exit_evt } = set_up_stall_monitor(1)?;

        exit_evt.signal()?;
        let _ = monitor
            .run(&exit_evt)?
            .join()
            .unwrap_or_else(|e| panic!("Thread join failed: {:?}", e));
        Ok(())
    }
}

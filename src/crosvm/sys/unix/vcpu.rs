// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::thread::JoinHandle;
#[cfg(target_arch = "x86_64")]
use std::time::Duration;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as Arch;
use anyhow::Context;
use anyhow::Result;
use arch::CpuConfigArch;
use arch::CpuSet;
use arch::IrqChipArch;
use arch::LinuxArch;
use arch::VcpuArch;
use arch::VcpuInitArch;
use arch::VmArch;
use base::signal::clear_signal_handler;
use base::signal::BlockedSignal;
use base::*;
use devices::Bus;
use devices::IrqChip;
use devices::VcpuRunState;
use hypervisor::IoOperation;
use hypervisor::IoParams;
use hypervisor::VcpuExit;
use hypervisor::VcpuSignalHandle;
use libc::c_int;
#[cfg(target_arch = "riscv64")]
use riscv64::Riscv64 as Arch;
#[cfg(all(target_arch = "x86_64", unix))]
use sync::Mutex;
use vm_control::*;
#[cfg(feature = "gdb")]
use vm_memory::GuestMemory;
#[cfg(target_arch = "x86_64")]
use x86_64::X8664arch as Arch;

use super::ExitState;
#[cfg(all(target_arch = "x86_64", unix))]
use crate::crosvm::ratelimit::Ratelimit;

fn bus_io_handler(bus: &Bus) -> impl FnMut(IoParams) -> Option<[u8; 8]> + '_ {
    |IoParams {
         address,
         mut size,
         operation: direction,
     }| match direction {
        IoOperation::Read => {
            let mut data = [0u8; 8];
            if size > data.len() {
                error!("unsupported Read size of {} bytes", size);
                size = data.len();
            }
            // Ignore the return value of `read()`. If no device exists on the bus at the given
            // location, return the initial value of data, which is all zeroes.
            let _ = bus.read(address, &mut data[..size]);
            Some(data)
        }
        IoOperation::Write { data } => {
            if size > data.len() {
                error!("unsupported Write size of {} bytes", size);
                size = data.len()
            }
            let data = &data[..size];
            bus.write(address, data);
            None
        }
    }
}

/// Set the VCPU thread affinity and other per-thread scheduler properties.
/// This function will be called from each VCPU thread at startup.
pub fn set_vcpu_thread_scheduling(
    vcpu_affinity: CpuSet,
    core_scheduling: bool,
    enable_per_vm_core_scheduling: bool,
    vcpu_cgroup_tasks_file: Option<File>,
    run_rt: bool,
) -> anyhow::Result<()> {
    if !vcpu_affinity.is_empty() {
        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
            error!("Failed to set CPU affinity: {}", e);
        }
    }

    if core_scheduling && !enable_per_vm_core_scheduling {
        // Do per-vCPU core scheduling by setting a unique cookie to each vCPU.
        if let Err(e) = enable_core_scheduling() {
            error!("Failed to enable core scheduling: {}", e);
        }
    }

    // Move vcpu thread to cgroup
    if let Some(mut f) = vcpu_cgroup_tasks_file {
        f.write_all(base::gettid().to_string().as_bytes())
            .context("failed to write vcpu tid to cgroup tasks")?;
    }

    if run_rt {
        const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
        if let Err(e) = set_rt_prio_limit(u64::from(DEFAULT_VCPU_RT_LEVEL))
            .and_then(|_| set_rt_round_robin(i32::from(DEFAULT_VCPU_RT_LEVEL)))
        {
            warn!("Failed to set vcpu to real time: {}", e);
        }
    }

    Ok(())
}

// Sets up a vcpu and converts it into a runnable vcpu.
pub fn runnable_vcpu<V>(
    cpu_id: usize,
    vcpu_id: usize,
    vcpu: Option<V>,
    vcpu_init: VcpuInitArch,
    vm: impl VmArch,
    irq_chip: &mut dyn IrqChipArch,
    vcpu_count: usize,
    cpu_config: Option<CpuConfigArch>,
) -> Result<V>
where
    V: VcpuArch,
{
    let mut vcpu = match vcpu {
        Some(v) => v,
        None => {
            // If vcpu is None, it means this arch/hypervisor requires create_vcpu to be called from
            // the vcpu thread.
            match vm
                .create_vcpu(vcpu_id)
                .context("failed to create vcpu")?
                .downcast::<V>()
            {
                Ok(v) => *v,
                Err(_) => panic!("VM created wrong type of VCPU"),
            }
        }
    };

    irq_chip
        .add_vcpu(cpu_id, &vcpu)
        .context("failed to add vcpu to irq chip")?;

    Arch::configure_vcpu(
        &vm,
        vm.get_hypervisor(),
        irq_chip,
        &mut vcpu,
        vcpu_init,
        cpu_id,
        vcpu_count,
        cpu_config,
    )
    .context("failed to configure vcpu")?;

    Ok(vcpu)
}

thread_local!(static VCPU_THREAD: RefCell<Option<VcpuSignalHandle>> = RefCell::new(None));

fn set_vcpu_thread_local(vcpu: Option<&dyn VcpuArch>, signal_num: c_int) {
    // Block signal while we add -- if a signal fires (very unlikely,
    // as this means something is trying to pause the vcpu before it has
    // even started) it'll try to grab the read lock while this write
    // lock is grabbed and cause a deadlock.
    // Assuming that a failure to block means it's already blocked.
    let _blocked_signal = BlockedSignal::new(signal_num);

    VCPU_THREAD.with(|v| {
        let mut vcpu_thread = v.borrow_mut();

        if let Some(vcpu) = vcpu {
            assert!(vcpu_thread.is_none());
            *vcpu_thread = Some(vcpu.signal_handle());
        } else {
            *vcpu_thread = None;
        }
    });
}

pub fn setup_vcpu_signal_handler() -> Result<()> {
    unsafe {
        extern "C" fn handle_signal(_: c_int) {
            // Use LocalKey::try_with() so we don't panic if a signal happens while the destructor
            // is running, and ignore any errors (the assumption being that the thread is exiting
            // anyway in that case).
            let _result = VCPU_THREAD.try_with(|v| {
                if let Some(vcpu_signal_handle) = &(*v.borrow()) {
                    vcpu_signal_handle.signal_immediate_exit();
                }
            });
        }

        register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
            .context("error registering signal handler")?;
    }
    Ok(())
}

pub fn remove_vcpu_signal_handler() -> Result<()> {
    clear_signal_handler(SIGRTMIN() + 0).context("error unregistering signal handler")
}

fn vcpu_loop<V>(
    mut run_mode: VmRunMode,
    cpu_id: usize,
    mut vcpu: V,
    irq_chip: Box<dyn IrqChipArch + 'static>,
    run_rt: bool,
    delay_rt: bool,
    io_bus: Bus,
    mmio_bus: Bus,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    #[cfg(feature = "gdb")] to_gdb_tube: Option<mpsc::Sender<VcpuDebugStatusMessage>>,
    #[cfg(feature = "gdb")] guest_mem: GuestMemory,
    #[cfg(all(target_arch = "x86_64", unix))] bus_lock_ratelimit_ctrl: Arc<Mutex<Ratelimit>>,
) -> ExitState
where
    V: VcpuArch,
{
    let mut interrupted_by_signal = false;

    loop {
        // Start by checking for messages to process and the run state of the CPU.
        // An extra check here for Running so there isn't a need to call recv unless a
        // message is likely to be ready because a signal was sent.
        if interrupted_by_signal || run_mode != VmRunMode::Running {
            'state_loop: loop {
                // Tries to get a pending message without blocking first.
                let msg = match from_main_tube.try_recv() {
                    Ok(m) => m,
                    Err(mpsc::TryRecvError::Empty) if run_mode == VmRunMode::Running => {
                        // If the VM is running and no message is pending, the state won't
                        // change.
                        break 'state_loop;
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        // If the VM is not running, wait until a message is ready.
                        match from_main_tube.recv() {
                            Ok(m) => m,
                            Err(mpsc::RecvError) => {
                                error!("Failed to read from main tube in vcpu");
                                return ExitState::Crash;
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        error!("Failed to read from main tube in vcpu");
                        return ExitState::Crash;
                    }
                };

                // Collect all pending messages.
                let mut messages = vec![msg];
                messages.append(&mut from_main_tube.try_iter().collect());

                for msg in messages {
                    match msg {
                        VcpuControl::RunState(new_mode) => {
                            run_mode = new_mode;
                            match run_mode {
                                VmRunMode::Running => {}
                                VmRunMode::Suspending => {
                                    if let Err(e) = vcpu.on_suspend() {
                                        error!(
                                            "failed to tell hypervisor vcpu {} is suspending: {}",
                                            cpu_id, e
                                        );
                                    }
                                }
                                VmRunMode::Breakpoint => {}
                                VmRunMode::Exiting => return ExitState::Stop,
                            }
                        }
                        #[cfg(feature = "gdb")]
                        VcpuControl::Debug(d) => {
                            if let Err(e) = crate::crosvm::gdb::vcpu_control_debug(
                                cpu_id,
                                &vcpu,
                                &guest_mem,
                                d,
                                to_gdb_tube.as_ref(),
                            ) {
                                error!("Failed to handle VcpuControl::Debug message: {:#}", e);
                            }
                        }
                        VcpuControl::MakeRT => {
                            if run_rt && delay_rt {
                                info!("Making vcpu {} RT\n", cpu_id);
                                const DEFAULT_VCPU_RT_LEVEL: u16 = 6;
                                if let Err(e) = set_rt_prio_limit(u64::from(DEFAULT_VCPU_RT_LEVEL))
                                    .and_then(|_| {
                                        set_rt_round_robin(i32::from(DEFAULT_VCPU_RT_LEVEL))
                                    })
                                {
                                    warn!("Failed to set vcpu to real time: {}", e);
                                }
                            }
                        }
                        VcpuControl::GetStates(response_chan) => {
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
                if run_mode == VmRunMode::Running {
                    break 'state_loop;
                }
            }
        }

        interrupted_by_signal = false;

        // Vcpus may have run a HLT instruction, which puts them into a state other than
        // VcpuRunState::Runnable. In that case, this call to wait_until_runnable blocks
        // until either the irqchip receives an interrupt for this vcpu, or until the main
        // thread kicks this vcpu as a result of some VmControl operation. In most IrqChip
        // implementations HLT instructions do not make it to crosvm, and thus this is a
        // no-op that always returns VcpuRunState::Runnable.
        match irq_chip.wait_until_runnable(vcpu.as_vcpu()) {
            Ok(VcpuRunState::Runnable) => {}
            Ok(VcpuRunState::Interrupted) => interrupted_by_signal = true,
            Err(e) => error!(
                "error waiting for vcpu {} to become runnable: {}",
                cpu_id, e
            ),
        }

        if !interrupted_by_signal {
            match vcpu.run() {
                Ok(VcpuExit::Io) => {
                    if let Err(e) = vcpu.handle_io(&mut bus_io_handler(&io_bus)) {
                        error!("failed to handle io: {}", e)
                    }
                }
                Ok(VcpuExit::Mmio) => {
                    if let Err(e) = vcpu.handle_mmio(&mut bus_io_handler(&mmio_bus)) {
                        error!("failed to handle mmio: {}", e);
                    }
                }
                Ok(VcpuExit::IoapicEoi { vector }) => {
                    if let Err(e) = irq_chip.broadcast_eoi(vector) {
                        error!(
                            "failed to broadcast eoi {} on vcpu {}: {}",
                            vector, cpu_id, e
                        );
                    }
                }
                Ok(VcpuExit::IrqWindowOpen) => {}
                Ok(VcpuExit::Hlt) => irq_chip.halted(cpu_id),
                Ok(VcpuExit::Shutdown) => return ExitState::Stop,
                Ok(VcpuExit::FailEntry {
                    hardware_entry_failure_reason,
                }) => {
                    error!("vcpu hw run failure: {:#x}", hardware_entry_failure_reason);
                    return ExitState::Crash;
                }
                Ok(VcpuExit::SystemEventShutdown) => {
                    info!("system shutdown event on vcpu {}", cpu_id);
                    return ExitState::Stop;
                }
                Ok(VcpuExit::SystemEventReset) => {
                    info!("system reset event");
                    return ExitState::Reset;
                }
                Ok(VcpuExit::SystemEventCrash) => {
                    info!("system crash event on vcpu {}", cpu_id);
                    return ExitState::Stop;
                }
                Ok(VcpuExit::Debug) => {
                    #[cfg(feature = "gdb")]
                    if let Err(e) =
                        crate::crosvm::gdb::vcpu_exit_debug(cpu_id, to_gdb_tube.as_ref())
                    {
                        error!("Failed to handle VcpuExit::Debug: {:#}", e);
                        return ExitState::Crash;
                    }

                    run_mode = VmRunMode::Breakpoint;
                }
                #[cfg(all(target_arch = "x86_64", unix))]
                Ok(VcpuExit::BusLock) => {
                    let delay_ns: u64 = bus_lock_ratelimit_ctrl.lock().ratelimit_calculate_delay(1);
                    thread::sleep(Duration::from_nanos(delay_ns));
                }
                Ok(VcpuExit::Sbi {
                    extension_id: _,
                    function_id: _,
                    args: _,
                }) => {
                    unimplemented!("Sbi exits not yet supported");
                }
                Ok(VcpuExit::RiscvCsr {
                    csr_num,
                    new_value,
                    write_mask,
                    ret_value: _,
                }) => {
                    unimplemented!(
                        "csr exit! {:#x} to {:#x} mask {:#x}",
                        csr_num,
                        new_value,
                        write_mask
                    );
                }

                Ok(r) => warn!("unexpected vcpu exit: {:?}", r),
                Err(e) => match e.errno() {
                    libc::EINTR => interrupted_by_signal = true,
                    libc::EAGAIN => {}
                    _ => {
                        error!("vcpu hit unknown error: {}", e);
                        return ExitState::Crash;
                    }
                },
            }
        }

        if interrupted_by_signal {
            vcpu.set_immediate_exit(false);
        }

        if let Err(e) = irq_chip.inject_interrupts(vcpu.as_vcpu()) {
            error!("failed to inject interrupts for vcpu {}: {}", cpu_id, e);
        }
    }
}

pub fn run_vcpu<V>(
    cpu_id: usize,
    vcpu_id: usize,
    vcpu: Option<V>,
    vcpu_init: VcpuInitArch,
    vm: impl VmArch + 'static,
    mut irq_chip: Box<dyn IrqChipArch + 'static>,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: CpuSet,
    delay_rt: bool,
    start_barrier: Arc<Barrier>,
    mut io_bus: Bus,
    mut mmio_bus: Bus,
    vm_evt_wrtube: SendTube,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    #[cfg(feature = "gdb")] to_gdb_tube: Option<mpsc::Sender<VcpuDebugStatusMessage>>,
    enable_core_scheduling: bool,
    enable_per_vm_core_scheduling: bool,
    cpu_config: Option<CpuConfigArch>,
    vcpu_cgroup_tasks_file: Option<File>,
    #[cfg(all(target_arch = "x86_64", unix))] bus_lock_ratelimit_ctrl: Arc<Mutex<Ratelimit>>,
    run_mode: VmRunMode,
) -> Result<JoinHandle<()>>
where
    V: VcpuArch + 'static,
{
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            // Having a closure returning ExitState guarentees that we
            // send a VmEventType on all code paths after the closure
            // returns.
            let vcpu_fn = || -> ExitState {
                if let Err(e) = set_vcpu_thread_scheduling(
                    vcpu_affinity,
                    enable_core_scheduling,
                    enable_per_vm_core_scheduling,
                    vcpu_cgroup_tasks_file,
                    run_rt && !delay_rt,
                ) {
                    error!("vcpu thread setup failed: {:#}", e);
                    return ExitState::Stop;
                }

                #[cfg(feature = "gdb")]
                let guest_mem = vm.get_memory().clone();

                let runnable_vcpu = runnable_vcpu(
                    cpu_id,
                    vcpu_id,
                    vcpu,
                    vcpu_init,
                    vm,
                    irq_chip.as_mut(),
                    vcpu_count,
                    cpu_config,
                );

                start_barrier.wait();

                let vcpu = match runnable_vcpu {
                    Ok(v) => v,
                    Err(e) => {
                        error!("failed to start vcpu {}: {:#}", cpu_id, e);
                        return ExitState::Stop;
                    }
                };

                set_vcpu_thread_local(Some(&vcpu), SIGRTMIN() + 0);

                mmio_bus.set_access_id(cpu_id);
                io_bus.set_access_id(cpu_id);

                let vcpu_exit_state = vcpu_loop(
                    run_mode,
                    cpu_id,
                    vcpu,
                    irq_chip,
                    run_rt,
                    delay_rt,
                    io_bus,
                    mmio_bus,
                    from_main_tube,
                    #[cfg(feature = "gdb")]
                    to_gdb_tube,
                    #[cfg(feature = "gdb")]
                    guest_mem,
                    #[cfg(all(target_arch = "x86_64", unix))]
                    bus_lock_ratelimit_ctrl,
                );

                // We don't want any more VCPU signals from now until the thread exits.
                let _ = block_signal(SIGRTMIN() + 0);
                set_vcpu_thread_local(None, SIGRTMIN() + 0);

                vcpu_exit_state
            };

            let final_event_data = match vcpu_fn() {
                ExitState::Stop => VmEventType::Exit,
                ExitState::Reset => VmEventType::Reset,
                ExitState::Crash => VmEventType::Crash,
                // vcpu_loop doesn't exit with GuestPanic.
                ExitState::GuestPanic => unreachable!(),
                ExitState::WatchdogReset => VmEventType::WatchdogReset,
            };
            if let Err(e) = vm_evt_wrtube.send::<VmEventType>(&final_event_data) {
                error!(
                    "failed to send final event {:?} on vcpu {}: {}",
                    final_event_data, cpu_id, e
                )
            }
        })
        .context("failed to spawn VCPU thread")
}

/// Signals all running VCPUs to vmexit, sends VcpuControl message to each VCPU tube, and tells
/// `irq_chip` to stop blocking halted VCPUs. The channel message is set first because both the
/// signal and the irq_chip kick could cause the VCPU thread to continue through the VCPU run
/// loop.
pub fn kick_all_vcpus(
    vcpu_handles: &[(JoinHandle<()>, mpsc::Sender<vm_control::VcpuControl>)],
    irq_chip: &dyn IrqChip,
    message: VcpuControl,
) {
    for (handle, tube) in vcpu_handles {
        if let Err(e) = tube.send(message.clone()) {
            error!("failed to send VcpuControl: {}", e);
        }
        let _ = handle.kill(SIGRTMIN() + 0);
    }
    irq_chip.kick_halted_vcpus();
}

/// Signals specific running VCPUs to vmexit, sends VcpuControl message to the VCPU tube, and tells
/// `irq_chip` to stop blocking halted VCPUs. The channel message is set first because both the
/// signal and the irq_chip kick could cause the VCPU thread to continue through the VCPU run
/// loop.
pub fn kick_vcpu(
    vcpu_handle: &Option<&(JoinHandle<()>, mpsc::Sender<vm_control::VcpuControl>)>,
    irq_chip: &dyn IrqChip,
    message: VcpuControl,
) {
    if let Some((handle, tube)) = vcpu_handle {
        if let Err(e) = tube.send(message) {
            error!("failed to send VcpuControl: {}", e);
        }
        let _ = handle.kill(SIGRTMIN() + 0);
    }
    irq_chip.kick_halted_vcpus();
}

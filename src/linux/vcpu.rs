// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::os::unix::fs::FileExt;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Barrier};

use std::thread;
use std::thread::JoinHandle;

use libc::{self, c_int};

use anyhow::{Context, Result};
use base::*;
use devices::{self, IrqChip, VcpuRunState};
use hypervisor::{Vcpu, VcpuExit, VcpuRunHandle};
use vm_control::*;
#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
use vm_memory::GuestMemory;

use arch::{self, LinuxArch};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use {
    aarch64::AArch64 as Arch,
    devices::IrqChipAArch64 as IrqChipArch,
    hypervisor::{VcpuAArch64 as VcpuArch, VmAArch64 as VmArch},
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use {
    devices::IrqChipX86_64 as IrqChipArch,
    hypervisor::{VcpuX86_64 as VcpuArch, VmX86_64 as VmArch},
    x86_64::X8664arch as Arch,
};

use super::ExitState;

pub fn setup_vcpu_signal_handler<T: Vcpu>(use_hypervisor_signals: bool) -> Result<()> {
    if use_hypervisor_signals {
        unsafe {
            extern "C" fn handle_signal(_: c_int) {}
            // Our signal handler does nothing and is trivially async signal safe.
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal)
                .context("error registering signal handler")?;
        }
        block_signal(SIGRTMIN() + 0).context("failed to block signal")?;
    } else {
        unsafe {
            extern "C" fn handle_signal<T: Vcpu>(_: c_int) {
                T::set_local_immediate_exit(true);
            }
            register_rt_signal_handler(SIGRTMIN() + 0, handle_signal::<T>)
                .context("error registering signal handler")?;
        }
    }
    Ok(())
}

// Sets up a vcpu and converts it into a runnable vcpu.
pub fn runnable_vcpu<V>(
    cpu_id: usize,
    kvm_vcpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch,
    irq_chip: &mut dyn IrqChipArch,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    no_smt: bool,
    has_bios: bool,
    use_hypervisor_signals: bool,
    enable_per_vm_core_scheduling: bool,
    host_cpu_topology: bool,
    vcpu_cgroup_tasks_file: Option<File>,
) -> Result<(V, VcpuRunHandle)>
where
    V: VcpuArch,
{
    let mut vcpu = match vcpu {
        Some(v) => v,
        None => {
            // If vcpu is None, it means this arch/hypervisor requires create_vcpu to be called from
            // the vcpu thread.
            match vm
                .create_vcpu(kvm_vcpu_id)
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

    if !vcpu_affinity.is_empty() {
        if let Err(e) = set_cpu_affinity(vcpu_affinity) {
            error!("Failed to set CPU affinity: {}", e);
        }
    }

    Arch::configure_vcpu(
        &vm,
        vm.get_hypervisor(),
        irq_chip,
        &mut vcpu,
        cpu_id,
        vcpu_count,
        has_bios,
        no_smt,
        host_cpu_topology,
    )
    .context("failed to configure vcpu")?;

    if !enable_per_vm_core_scheduling {
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

    if use_hypervisor_signals {
        let mut v = get_blocked_signals().context("failed to retrieve signal mask for vcpu")?;
        v.retain(|&x| x != SIGRTMIN() + 0);
        vcpu.set_signal_mask(&v)
            .context("failed to set the signal mask for vcpu")?;
    }

    let vcpu_run_handle = vcpu
        .take_run_handle(Some(SIGRTMIN() + 0))
        .context("failed to set thread id for vcpu")?;

    Ok((vcpu, vcpu_run_handle))
}

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
fn handle_debug_msg<V>(
    cpu_id: usize,
    vcpu: &V,
    guest_mem: &GuestMemory,
    d: VcpuDebug,
    reply_tube: &mpsc::Sender<VcpuDebugStatusMessage>,
) -> Result<()>
where
    V: VcpuArch + 'static,
{
    match d {
        VcpuDebug::ReadRegs => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::RegValues(
                    Arch::debug_read_registers(vcpu as &V)
                        .context("failed to handle a gdb ReadRegs command")?,
                ),
            };
            reply_tube
                .send(msg)
                .context("failed to send a debug status to GDB thread")
        }
        VcpuDebug::WriteRegs(regs) => {
            Arch::debug_write_registers(vcpu as &V, &regs)
                .context("failed to handle a gdb WriteRegs command")?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .context("failed to send a debug status to GDB thread")
        }
        VcpuDebug::ReadMem(vaddr, len) => {
            let msg = VcpuDebugStatusMessage {
                cpu: cpu_id as usize,
                msg: VcpuDebugStatus::MemoryRegion(
                    Arch::debug_read_memory(vcpu as &V, guest_mem, vaddr, len)
                        .unwrap_or(Vec::new()),
                ),
            };
            reply_tube
                .send(msg)
                .context("failed to send a debug status to GDB thread")
        }
        VcpuDebug::WriteMem(vaddr, buf) => {
            Arch::debug_write_memory(vcpu as &V, guest_mem, vaddr, &buf)
                .context("failed to handle a gdb WriteMem command")?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .context("failed to send a debug status to GDB thread")
        }
        VcpuDebug::EnableSinglestep => {
            Arch::debug_enable_singlestep(vcpu as &V)
                .context("failed to handle a gdb EnableSingleStep command")?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .context("failed to send a debug status to GDB thread")
        }
        VcpuDebug::SetHwBreakPoint(addrs) => {
            Arch::debug_set_hw_breakpoints(vcpu as &V, &addrs)
                .context("failed to handle a gdb SetHwBreakPoint command")?;
            reply_tube
                .send(VcpuDebugStatusMessage {
                    cpu: cpu_id as usize,
                    msg: VcpuDebugStatus::CommandComplete,
                })
                .context("failed to send a debug status to GDB thread")
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn handle_s2idle_request(_privileged_vm: bool) {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn handle_s2idle_request(privileged_vm: bool) {
    const POWER_STATE_FREEZE: &[u8] = b"freeze";

    // For non privileged guests, we silently ignore the suspend request
    if !privileged_vm {
        return;
    }

    let mut power_state = match OpenOptions::new().write(true).open("/sys/power/state") {
        Ok(s) => s,
        Err(err) => {
            error!("Failed on open /sys/power/state: {}", err);
            return;
        }
    };

    if let Err(err) = power_state.write(POWER_STATE_FREEZE) {
        error!("Failed on writing to /sys/power/state: {}", err);
        return;
    }
}

fn vcpu_loop<V>(
    mut run_mode: VmRunMode,
    cpu_id: usize,
    vcpu: V,
    vcpu_run_handle: VcpuRunHandle,
    irq_chip: Box<dyn IrqChipArch + 'static>,
    run_rt: bool,
    delay_rt: bool,
    io_bus: devices::Bus,
    mmio_bus: devices::Bus,
    requires_pvclock_ctrl: bool,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    use_hypervisor_signals: bool,
    privileged_vm: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))] to_gdb_tube: Option<
        mpsc::Sender<VcpuDebugStatusMessage>,
    >,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))] guest_mem: GuestMemory,
    msr_handlers: MsrHandlers,
) -> ExitState
where
    V: VcpuArch + 'static,
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
                                VmRunMode::Running => break 'state_loop,
                                VmRunMode::Suspending => {
                                    // On KVM implementations that use a paravirtualized
                                    // clock (e.g. x86), a flag must be set to indicate to
                                    // the guest kernel that a vCPU was suspended. The guest
                                    // kernel will use this flag to prevent the soft lockup
                                    // detection from triggering when this vCPU resumes,
                                    // which could happen days later in realtime.
                                    if requires_pvclock_ctrl {
                                        if let Err(e) = vcpu.pvclock_ctrl() {
                                            error!(
                                                "failed to tell hypervisor vcpu {} is suspending: {}",
                                                cpu_id, e
                                            );
                                        }
                                    }
                                }
                                VmRunMode::Breakpoint => {}
                                VmRunMode::Exiting => return ExitState::Stop,
                            }
                        }
                        #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                        VcpuControl::Debug(d) => match &to_gdb_tube {
                            Some(ref ch) => {
                                if let Err(e) = handle_debug_msg(cpu_id, &vcpu, &guest_mem, d, ch) {
                                    error!("Failed to handle gdb message: {}", e);
                                }
                            }
                            None => {
                                error!("VcpuControl::Debug received while GDB feature is disabled: {:?}", d);
                            }
                        },
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
                    }
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
        match irq_chip.wait_until_runnable(&vcpu) {
            Ok(VcpuRunState::Runnable) => {}
            Ok(VcpuRunState::Interrupted) => interrupted_by_signal = true,
            Err(e) => error!(
                "error waiting for vcpu {} to become runnable: {}",
                cpu_id, e
            ),
        }

        if !interrupted_by_signal {
            match vcpu.run(&vcpu_run_handle) {
                Ok(VcpuExit::IoIn { port, mut size }) => {
                    let mut data = [0; 8];
                    if size > data.len() {
                        error!(
                            "unsupported IoIn size of {} bytes at port {:#x}",
                            size, port
                        );
                        size = data.len();
                    }
                    io_bus.read(port as u64, &mut data[..size]);
                    if let Err(e) = vcpu.set_data(&data[..size]) {
                        error!(
                            "failed to set return data for IoIn at port {:#x}: {}",
                            port, e
                        );
                    }
                }
                Ok(VcpuExit::IoOut {
                    port,
                    mut size,
                    data,
                }) => {
                    if size > data.len() {
                        error!(
                            "unsupported IoOut size of {} bytes at port {:#x}",
                            size, port
                        );
                        size = data.len();
                    }
                    io_bus.write(port as u64, &data[..size]);
                }
                Ok(VcpuExit::MmioRead { address, size }) => {
                    let mut data = [0; 8];
                    mmio_bus.read(address, &mut data[..size]);
                    // Setting data for mmio can not fail.
                    let _ = vcpu.set_data(&data[..size]);
                }
                Ok(VcpuExit::MmioWrite {
                    address,
                    size,
                    data,
                }) => {
                    mmio_bus.write(address, &data[..size]);
                }
                Ok(VcpuExit::RdMsr { index }) => {
                    if let Some(data) = msr_handlers.read(index) {
                        let _ = vcpu.set_data(&data.to_ne_bytes());
                    }
                }
                Ok(VcpuExit::WrMsr { .. }) => {
                    // TODO(b/215297064): implement MSR write
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
                Ok(VcpuExit::SystemEventS2Idle) => {
                    handle_s2idle_request(privileged_vm);
                }
                #[rustfmt::skip] Ok(VcpuExit::Debug { .. }) => {
                    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                    {
                        let msg = VcpuDebugStatusMessage {
                            cpu: cpu_id as usize,
                            msg: VcpuDebugStatus::HitBreakPoint,
                        };
                        if let Some(ref ch) = to_gdb_tube {
                            if let Err(e) = ch.send(msg) {
                                error!("failed to notify breakpoint to GDB thread: {}", e);
                                return ExitState::Crash;
                            }
                        }
                        run_mode = VmRunMode::Breakpoint;
                    }
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
            if use_hypervisor_signals {
                // Try to clear the signal that we use to kick VCPU if it is pending before
                // attempting to handle pause requests.
                if let Err(e) = clear_signal(SIGRTMIN() + 0) {
                    error!("failed to clear pending signal: {}", e);
                    return ExitState::Crash;
                }
            } else {
                vcpu.set_immediate_exit(false);
            }
        }

        if let Err(e) = irq_chip.inject_interrupts(&vcpu) {
            error!("failed to inject interrupts for vcpu {}: {}", cpu_id, e);
        }
    }
}

trait MsrHandling {
    fn read(&self, index: u32) -> Result<u64>;
    fn write(&self, index: u32, data: u64) -> Result<()>;
}

struct ReadPassthrough {
    dev_msr: std::fs::File,
}

impl MsrHandling for ReadPassthrough {
    fn read(&self, index: u32) -> Result<u64> {
        let mut data = [0; 8];
        self.dev_msr.read_exact_at(&mut data, index.into())?;
        Ok(u64::from_ne_bytes(data))
    }

    fn write(&self, _index: u32, _data: u64) -> Result<()> {
        // TODO(b/215297064): implement MSR write
        unimplemented!();
    }
}

impl ReadPassthrough {
    fn new() -> Result<Self> {
        // TODO(b/215297064): Support reading from other CPUs than 0, should match running CPU.
        let filename = "/dev/cpu/0/msr";
        let dev_msr = OpenOptions::new()
            .read(true)
            .open(&filename)
            .context("Cannot open /dev/cpu/0/msr, are you root?")?;
        Ok(ReadPassthrough { dev_msr })
    }
}

/// MSR handler configuration. Per-cpu.
struct MsrHandlers {
    handler: BTreeMap<u32, Rc<Box<dyn MsrHandling>>>,
}

impl MsrHandlers {
    fn new() -> Self {
        MsrHandlers {
            handler: BTreeMap::new(),
        }
    }

    fn read(&self, index: u32) -> Option<u64> {
        if let Some(handler) = self.handler.get(&index) {
            match handler.read(index) {
                Ok(data) => Some(data),
                Err(e) => {
                    error!("MSR host read failed {:#x} {:?}", index, e);
                    None
                }
            }
        } else {
            None
        }
    }
}

pub fn run_vcpu<V>(
    cpu_id: usize,
    kvm_vcpu_id: usize,
    vcpu: Option<V>,
    vm: impl VmArch + 'static,
    mut irq_chip: Box<dyn IrqChipArch + 'static>,
    vcpu_count: usize,
    run_rt: bool,
    vcpu_affinity: Vec<usize>,
    delay_rt: bool,
    no_smt: bool,
    start_barrier: Arc<Barrier>,
    has_bios: bool,
    mut io_bus: devices::Bus,
    mut mmio_bus: devices::Bus,
    exit_evt: Event,
    reset_evt: Event,
    crash_evt: Event,
    requires_pvclock_ctrl: bool,
    from_main_tube: mpsc::Receiver<VcpuControl>,
    use_hypervisor_signals: bool,
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))] to_gdb_tube: Option<
        mpsc::Sender<VcpuDebugStatusMessage>,
    >,
    enable_per_vm_core_scheduling: bool,
    host_cpu_topology: bool,
    privileged_vm: bool,
    vcpu_cgroup_tasks_file: Option<File>,
    userspace_msr: BTreeSet<u32>,
) -> Result<JoinHandle<()>>
where
    V: VcpuArch + 'static,
{
    thread::Builder::new()
        .name(format!("crosvm_vcpu{}", cpu_id))
        .spawn(move || {
            // The VCPU thread must trigger either `exit_evt` or `reset_event` in all paths. A
            // `ScopedEvent`'s Drop implementation ensures that the `exit_evt` will be sent if
            // anything happens before we get to writing the final event.
            let scoped_exit_evt = ScopedEvent::from(exit_evt);

            let mut msr_handlers = MsrHandlers::new();
            if !userspace_msr.is_empty() {
                let read_passthrough: Rc<Box<dyn MsrHandling>> = match ReadPassthrough::new() {
                    Ok(r) => Rc::new(Box::new(r)),
                    Err(e) => {
                        error!(
                            "failed to create MSR read passthrough handler for vcpu {}: {:#}",
                            cpu_id, e
                        );
                        return;
                    }
                };

                userspace_msr.iter().for_each(|&index| {
                    msr_handlers.handler.insert(index, read_passthrough.clone());
                });
            }

            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            let guest_mem = vm.get_memory().clone();
            let runnable_vcpu = runnable_vcpu(
                cpu_id,
                kvm_vcpu_id,
                vcpu,
                vm,
                irq_chip.as_mut(),
                vcpu_count,
                run_rt && !delay_rt,
                vcpu_affinity,
                no_smt,
                has_bios,
                use_hypervisor_signals,
                enable_per_vm_core_scheduling,
                host_cpu_topology,
                vcpu_cgroup_tasks_file,
            );

            start_barrier.wait();

            let (vcpu, vcpu_run_handle) = match runnable_vcpu {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to start vcpu {}: {:#}", cpu_id, e);
                    return;
                }
            };

            #[allow(unused_mut)]
            let mut run_mode = VmRunMode::Running;
            #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
            if to_gdb_tube.is_some() {
                // Wait until a GDB client attaches
                run_mode = VmRunMode::Breakpoint;
            }

            mmio_bus.set_access_id(cpu_id);
            io_bus.set_access_id(cpu_id);

            let exit_reason = vcpu_loop(
                run_mode,
                cpu_id,
                vcpu,
                vcpu_run_handle,
                irq_chip,
                run_rt,
                delay_rt,
                io_bus,
                mmio_bus,
                requires_pvclock_ctrl,
                from_main_tube,
                use_hypervisor_signals,
                privileged_vm,
                #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                to_gdb_tube,
                #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
                guest_mem,
                msr_handlers,
            );

            let exit_evt = scoped_exit_evt.into();
            let final_event = match exit_reason {
                ExitState::Stop => Some(exit_evt),
                ExitState::Reset => Some(reset_evt),
                ExitState::Crash => Some(crash_evt),
                // vcpu_loop doesn't exit with GuestPanic.
                ExitState::GuestPanic => None,
            };
            if let Some(final_event) = final_event {
                if let Err(e) = final_event.write(1) {
                    error!(
                        "failed to send final event {:?} on vcpu {}: {}",
                        final_event, cpu_id, e
                    )
                }
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

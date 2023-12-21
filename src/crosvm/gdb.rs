// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use aarch64::AArch64 as CrosvmArch;
use anyhow::Context;
use arch::GdbArch;
use arch::VcpuArch;
use base::error;
use base::info;
use base::Tube;
use base::TubeError;
use gdbstub::arch::Arch;
use gdbstub::common::Signal;
use gdbstub::conn::Connection;
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::run_blocking;
use gdbstub::stub::run_blocking::BlockingEventLoop;
use gdbstub::stub::SingleThreadStopReason;
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccess;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use gdbstub::target::ext::base::single_register_access::SingleRegisterAccessOps;
use gdbstub::target::ext::base::singlethread::SingleThreadBase;
use gdbstub::target::ext::base::singlethread::SingleThreadResume;
use gdbstub::target::ext::base::singlethread::SingleThreadResumeOps;
use gdbstub::target::ext::base::singlethread::SingleThreadSingleStep;
use gdbstub::target::ext::base::singlethread::SingleThreadSingleStepOps;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::Breakpoints;
use gdbstub::target::ext::breakpoints::BreakpointsOps;
use gdbstub::target::ext::breakpoints::HwBreakpoint;
use gdbstub::target::ext::breakpoints::HwBreakpointOps;
use gdbstub::target::Target;
use gdbstub::target::TargetError::NonFatal;
use gdbstub::target::TargetResult;
use remain::sorted;
#[cfg(target_arch = "riscv64")]
use riscv64::Riscv64 as CrosvmArch;
use sync::Mutex;
use thiserror::Error as ThisError;
use vm_control::VcpuControl;
use vm_control::VcpuDebug;
use vm_control::VcpuDebugStatus;
use vm_control::VcpuDebugStatusMessage;
use vm_control::VmRequest;
use vm_control::VmResponse;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
#[cfg(target_arch = "x86_64")]
use x86_64::X8664arch as CrosvmArch;

pub fn gdb_thread(mut gdbstub: GdbStub, port: u32) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(addr.clone()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create a TCP listener: {}", e);
            return;
        }
    };
    info!("Waiting for a GDB connection on {:?}...", addr);

    let (stream, addr) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to accept a connection from GDB: {}", e);
            return;
        }
    };
    info!("GDB connected from {}", addr);

    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = Box::new(stream);
    let gdb = gdbstub::stub::GdbStub::new(connection);

    match gdb.run_blocking::<GdbStubEventLoop>(&mut gdbstub) {
        Ok(reason) => {
            info!("GDB session closed: {:?}", reason);
        }
        Err(e) => {
            error!("error occurred in GDB session: {}", e);
        }
    }

    // Resume the VM when GDB session is disconnected.
    if let Err(e) = gdbstub.vm_request(VmRequest::ResumeVcpus) {
        error!("Failed to resume the VM after GDB disconnected: {}", e);
    }
}

#[sorted]
#[derive(ThisError, Debug)]
enum Error {
    /// Got an unexpected VM response.
    #[error("Got an unexpected VM response: {0}")]
    UnexpectedVmResponse(VmResponse),
    /// Failed to send a vCPU request.
    #[error("failed to send a vCPU request: {0}")]
    VcpuRequest(mpsc::SendError<VcpuControl>),
    /// Failed to receive a vCPU response.
    #[error("failed to receive a vCPU response: {0}")]
    VcpuResponse(mpsc::RecvTimeoutError),
    /// Failed to send a VM request.
    #[error("failed to send a VM request: {0}")]
    VmRequest(TubeError),
    /// Failed to receive a VM request.
    #[error("failed to receive a VM response: {0}")]
    VmResponse(TubeError),
}
type GdbResult<T> = std::result::Result<T, Error>;

pub struct GdbStub {
    vm_tube: Mutex<Tube>,
    vcpu_com: Vec<mpsc::Sender<VcpuControl>>,
    from_vcpu: mpsc::Receiver<VcpuDebugStatusMessage>,

    single_step: bool,
    max_hw_breakpoints: Option<usize>,
    hw_breakpoints: Vec<GuestAddress>,
}

impl GdbStub {
    pub fn new(
        vm_tube: Tube,
        vcpu_com: Vec<mpsc::Sender<VcpuControl>>,
        from_vcpu: mpsc::Receiver<VcpuDebugStatusMessage>,
    ) -> Self {
        GdbStub {
            vm_tube: Mutex::new(vm_tube),
            vcpu_com,
            from_vcpu,
            single_step: false,
            max_hw_breakpoints: None,
            hw_breakpoints: Default::default(),
        }
    }

    fn vcpu_request(&self, request: VcpuControl) -> GdbResult<VcpuDebugStatus> {
        // We use the only one vCPU when GDB is enabled.
        self.vcpu_com[0].send(request).map_err(Error::VcpuRequest)?;

        match self.from_vcpu.recv_timeout(Duration::from_millis(500)) {
            Ok(msg) => Ok(msg.msg),
            Err(e) => Err(Error::VcpuResponse(e)),
        }
    }

    fn vm_request(&self, request: VmRequest) -> GdbResult<()> {
        let vm_tube = self.vm_tube.lock();
        vm_tube.send(&request).map_err(Error::VmRequest)?;
        match vm_tube.recv() {
            Ok(VmResponse::Ok) => Ok(()),
            Ok(r) => Err(Error::UnexpectedVmResponse(r)),
            Err(e) => Err(Error::VmResponse(e)),
        }
    }

    fn max_hw_breakpoints_request(&self) -> TargetResult<usize, Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::GetHwBreakPointCount)) {
            Ok(VcpuDebugStatus::HwBreakPointCount(n)) => Ok(n),
            Ok(s) => {
                error!("Unexpected vCPU response for GetHwBreakPointCount: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request GetHwBreakPointCount: {}", e);
                Err(NonFatal)
            }
        }
    }
}

impl Target for GdbStub {
    type Arch = GdbArch;
    type Error = &'static str;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    // TODO(keiichiw): sw_breakpoint, hw_watchpoint, extended_mode, monitor_cmd, section_offsets
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

    // TODO(crbug.com/1141812): Remove this override once proper software breakpoint
    // support has been added.
    //
    // Overriding this method to return `true` allows GDB to implement software
    // breakpoints by writing breakpoint instructions directly into the target's
    // instruction stream. This will be redundant once proper software breakpoints
    // have been implemented. See the trait method's docs for more information:
    // https://docs.rs/gdbstub/0.6.1/gdbstub/target/trait.Target.html#method.guard_rail_implicit_sw_breakpoints
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}

impl SingleThreadBase for GdbStub {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::ReadRegs)) {
            Ok(VcpuDebugStatus::RegValues(r)) => {
                *regs = r;
                Ok(())
            }
            Ok(s) => {
                error!("Unexpected vCPU response for ReadRegs: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request ReadRegs: {}", e);
                Err(NonFatal)
            }
        }
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::WriteRegs(Box::new(
            regs.clone(),
        )))) {
            Ok(VcpuDebugStatus::CommandComplete) => Ok(()),
            Ok(s) => {
                error!("Unexpected vCPU response for WriteRegs: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request WriteRegs: {}", e);
                Err(NonFatal)
            }
        }
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::ReadMem(
            GuestAddress(start_addr),
            data.len(),
        ))) {
            Ok(VcpuDebugStatus::MemoryRegion(r)) => {
                for (dst, v) in data.iter_mut().zip(r.iter()) {
                    *dst = *v;
                }
                Ok(data.len())
            }
            Ok(s) => {
                error!("Unexpected vCPU response for ReadMem: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request ReadMem: {}", e);
                Err(NonFatal)
            }
        }
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::WriteMem(
            GuestAddress(start_addr),
            data.to_owned(),
        ))) {
            Ok(VcpuDebugStatus::CommandComplete) => Ok(()),
            Ok(s) => {
                error!("Unexpected vCPU response for WriteMem: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request WriteMem: {}", e);
                Err(NonFatal)
            }
        }
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    #[inline(always)]
    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<(), Self>> {
        Some(self)
    }
}

impl SingleThreadResume for GdbStub {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        // TODO: Handle any incoming signal.

        self.vm_request(VmRequest::ResumeVcpus).map_err(|e| {
            error!("Failed to resume the target: {}", e);
            "Failed to resume the target"
        })
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl SingleThreadSingleStep for GdbStub {
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), Self::Error> {
        // TODO: Handle any incoming signal.

        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::EnableSinglestep)) {
            Ok(VcpuDebugStatus::CommandComplete) => {
                self.single_step = true;
            }
            Ok(s) => {
                error!("Unexpected vCPU response for EnableSinglestep: {:?}", s);
                return Err("Unexpected vCPU response for EnableSinglestep");
            }
            Err(e) => {
                error!("Failed to request EnableSinglestep: {}", e);
                return Err("Failed to request EnableSinglestep");
            }
        };

        self.vm_request(VmRequest::ResumeVcpus).map_err(|e| {
            error!("Failed to resume the target: {}", e);
            "Failed to resume the target"
        })?;

        Ok(())
    }
}

impl Breakpoints for GdbStub {
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }
}

impl HwBreakpoint for GdbStub {
    /// Add a new hardware breakpoint.
    /// Return `Ok(false)` if the operation could not be completed.
    fn add_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let max_count = *(match &mut self.max_hw_breakpoints {
            None => self
                .max_hw_breakpoints
                .insert(self.max_hw_breakpoints_request()?),
            Some(c) => c,
        });
        if self.hw_breakpoints.len() >= max_count {
            error!("Not allowed to set more than {} HW breakpoints", max_count);
            return Err(NonFatal);
        }
        self.hw_breakpoints.push(GuestAddress(addr));

        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::SetHwBreakPoint(
            self.hw_breakpoints.clone(),
        ))) {
            Ok(VcpuDebugStatus::CommandComplete) => Ok(true),
            Ok(s) => {
                error!("Unexpected vCPU response for SetHwBreakPoint: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request SetHwBreakPoint: {}", e);
                Err(NonFatal)
            }
        }
    }

    /// Remove an existing hardware breakpoint.
    /// Return `Ok(false)` if the operation could not be completed.
    fn remove_hw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        self.hw_breakpoints.retain(|&b| b.0 != addr);

        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::SetHwBreakPoint(
            self.hw_breakpoints.clone(),
        ))) {
            Ok(VcpuDebugStatus::CommandComplete) => Ok(true),
            Ok(s) => {
                error!("Unexpected vCPU response for SetHwBreakPoint: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request SetHwBreakPoint: {}", e);
                Err(NonFatal)
            }
        }
    }
}

impl SingleRegisterAccess<()> for GdbStub {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as Arch>::RegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::ReadReg(reg_id))) {
            Ok(VcpuDebugStatus::RegValue(r)) => {
                if buf.len() != r.len() {
                    error!(
                        "Register size mismatch in RegValue: {} != {}",
                        buf.len(),
                        r.len()
                    );
                    return Err(NonFatal);
                }
                for (dst, v) in buf.iter_mut().zip(r.iter()) {
                    *dst = *v;
                }
                Ok(r.len())
            }
            Ok(s) => {
                error!("Unexpected vCPU response for ReadReg: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request ReadReg: {}", e);
                Err(NonFatal)
            }
        }
    }

    fn write_register(
        &mut self,
        _tid: (),
        reg_id: <Self::Arch as Arch>::RegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::WriteReg(
            reg_id,
            val.to_owned(),
        ))) {
            Ok(VcpuDebugStatus::CommandComplete) => Ok(()),
            Ok(s) => {
                error!("Unexpected vCPU response for WriteReg: {:?}", s);
                Err(NonFatal)
            }
            Err(e) => {
                error!("Failed to request WriteReg: {}", e);
                Err(NonFatal)
            }
        }
    }
}

struct GdbStubEventLoop;

impl BlockingEventLoop for GdbStubEventLoop {
    type Target = GdbStub;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;
    type StopReason = SingleThreadStopReason<<GdbArch as Arch>::Usize>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        loop {
            // TODO(keiichiw): handle error?
            if let Ok(msg) = target
                .from_vcpu
                .recv_timeout(std::time::Duration::from_millis(100))
            {
                match msg.msg {
                    VcpuDebugStatus::HitBreakPoint => {
                        if target.single_step {
                            target.single_step = false;
                            return Ok(run_blocking::Event::TargetStopped(
                                SingleThreadStopReason::DoneStep,
                            ));
                        } else {
                            return Ok(run_blocking::Event::TargetStopped(
                                SingleThreadStopReason::HwBreak(()),
                            ));
                        }
                    }
                    status => {
                        error!("Unexpected VcpuDebugStatus: {:?}", status);
                    }
                }
            }

            // If no message was received within the timeout check for incoming data from
            // the GDB client.
            if conn
                .peek()
                .map_err(run_blocking::WaitForStopReasonError::Connection)?
                .is_some()
            {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    fn on_interrupt(
        target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as Target>::Error> {
        target.vm_request(VmRequest::SuspendVcpus).map_err(|e| {
            error!("Failed to suspend the target: {}", e);
            "Failed to suspend the target"
        })?;

        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

/// Notify the GDB thread that a VCPU has stopped because of a breakpoint.
pub fn vcpu_exit_debug(
    cpu: usize,
    to_gdb_tube: Option<&mpsc::Sender<VcpuDebugStatusMessage>>,
) -> anyhow::Result<()> {
    if let Some(ch) = to_gdb_tube.as_ref() {
        ch.send(VcpuDebugStatusMessage {
            cpu,
            msg: VcpuDebugStatus::HitBreakPoint,
        })
        .context("failed to send breakpoint status to gdb thread")?;
    }
    Ok(())
}

/// Handle a `VcpuDebug` request for a given `vcpu`.
pub fn vcpu_control_debug<V>(
    cpu_id: usize,
    vcpu: &V,
    guest_mem: &GuestMemory,
    d: VcpuDebug,
    reply_tube: Option<&mpsc::Sender<VcpuDebugStatusMessage>>,
) -> anyhow::Result<()>
where
    V: VcpuArch + 'static,
{
    let reply_tube = reply_tube
        .as_ref()
        .context("VcpuControl::Debug received while debugger not connected")?;

    let debug_status = match d {
        VcpuDebug::ReadRegs => VcpuDebugStatus::RegValues(
            <CrosvmArch as arch::GdbOps<V>>::read_registers(vcpu as &V)
                .context("failed to handle a gdb ReadRegs command")?,
        ),
        VcpuDebug::WriteRegs(regs) => {
            <CrosvmArch as arch::GdbOps<V>>::write_registers(vcpu as &V, &regs)
                .context("failed to handle a gdb WriteRegs command")?;
            VcpuDebugStatus::CommandComplete
        }
        VcpuDebug::ReadReg(reg) => VcpuDebugStatus::RegValue(
            <CrosvmArch as arch::GdbOps<V>>::read_register(vcpu as &V, reg)
                .context("failed to handle a gdb ReadReg command")?,
        ),
        VcpuDebug::WriteReg(reg, buf) => {
            <CrosvmArch as arch::GdbOps<V>>::write_register(vcpu as &V, reg, &buf)
                .context("failed to handle a gdb WriteReg command")?;
            VcpuDebugStatus::CommandComplete
        }
        VcpuDebug::ReadMem(vaddr, len) => VcpuDebugStatus::MemoryRegion(
            <CrosvmArch as arch::GdbOps<V>>::read_memory(vcpu as &V, guest_mem, vaddr, len)
                .unwrap_or_default(),
        ),
        VcpuDebug::WriteMem(vaddr, buf) => {
            <CrosvmArch as arch::GdbOps<V>>::write_memory(vcpu as &V, guest_mem, vaddr, &buf)
                .context("failed to handle a gdb WriteMem command")?;
            VcpuDebugStatus::CommandComplete
        }
        VcpuDebug::EnableSinglestep => {
            <CrosvmArch as arch::GdbOps<V>>::enable_singlestep(vcpu as &V)
                .context("failed to handle a gdb EnableSingleStep command")?;
            VcpuDebugStatus::CommandComplete
        }
        VcpuDebug::GetHwBreakPointCount => VcpuDebugStatus::HwBreakPointCount(
            <CrosvmArch as arch::GdbOps<V>>::get_max_hw_breakpoints(vcpu as &V)
                .context("failed to get max number of HW breakpoints")?,
        ),
        VcpuDebug::SetHwBreakPoint(addrs) => {
            <CrosvmArch as arch::GdbOps<V>>::set_hw_breakpoints(vcpu as &V, &addrs)
                .context("failed to handle a gdb SetHwBreakPoint command")?;
            VcpuDebugStatus::CommandComplete
        }
    };

    reply_tube
        .send(VcpuDebugStatusMessage {
            cpu: cpu_id,
            msg: debug_status,
        })
        .context("failed to send a debug status to GDB thread")
}

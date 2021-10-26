// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use base::{error, info, Tube, TubeError};

use sync::Mutex;
use vm_control::{
    VcpuControl, VcpuDebug, VcpuDebugStatus, VcpuDebugStatusMessage, VmRequest, VmResponse,
};
use vm_memory::GuestAddress;

use gdbstub::arch::Arch;
use gdbstub::target::ext::base::singlethread::{ResumeAction, SingleThreadOps, StopReason};
use gdbstub::target::ext::base::{BaseOps, GdbInterrupt};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps,
};
use gdbstub::target::TargetError::NonFatal;
use gdbstub::target::{Target, TargetResult};
use gdbstub::Connection;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbArch;
use remain::sorted;
use thiserror::Error as ThisError;

#[cfg(target_arch = "x86_64")]
type ArchUsize = u64;

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

    let connection: Box<dyn Connection<Error = std::io::Error>> = Box::new(stream);
    let mut gdb = gdbstub::GdbStub::new(connection);

    match gdb.run(&mut gdbstub) {
        Ok(reason) => {
            info!("GDB session closed: {:?}", reason);
        }
        Err(e) => {
            error!("error occurred in GDB session: {}", e);
        }
    }

    // Resume the VM when GDB session is disconnected.
    if let Err(e) = gdbstub.vm_request(VmRequest::Resume) {
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
}

impl Target for GdbStub {
    // TODO(keiichiw): Replace `()` with `X86_64CoreRegId` when we update the gdbstub crate.
    type Arch = GdbArch<()>;
    type Error = &'static str;

    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    // TODO(keiichiw): sw_breakpoint, hw_watchpoint, extended_mode, monitor_cmd, section_offsets
    fn breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }
}

impl SingleThreadOps for GdbStub {
    fn resume(
        &mut self,
        action: ResumeAction,
        check_gdb_interrupt: GdbInterrupt,
    ) -> Result<StopReason<ArchUsize>, Self::Error> {
        let single_step = ResumeAction::Step == action;

        if single_step {
            match self.vcpu_request(VcpuControl::Debug(VcpuDebug::EnableSinglestep)) {
                Ok(VcpuDebugStatus::CommandComplete) => {}
                Ok(s) => {
                    error!("Unexpected vCPU response for EnableSinglestep: {:?}", s);
                    return Err("Unexpected vCPU response for EnableSinglestep");
                }
                Err(e) => {
                    error!("Failed to request EnableSinglestep: {}", e);
                    return Err("Failed to request EnableSinglestep");
                }
            };
        }

        self.vm_request(VmRequest::Resume).map_err(|e| {
            error!("Failed to resume the target: {}", e);
            "Failed to resume the target"
        })?;

        let mut check_gdb_interrupt = check_gdb_interrupt.no_async();
        // Polling
        loop {
            // TODO(keiichiw): handle error?
            if let Ok(msg) = self
                .from_vcpu
                .recv_timeout(std::time::Duration::from_millis(100))
            {
                match msg.msg {
                    VcpuDebugStatus::HitBreakPoint => {
                        if single_step {
                            return Ok(StopReason::DoneStep);
                        } else {
                            return Ok(StopReason::HwBreak);
                        }
                    }
                    status => {
                        error!("Unexpected VcpuDebugStatus: {:?}", status);
                    }
                }
            }

            if check_gdb_interrupt.pending() {
                self.vm_request(VmRequest::Suspend).map_err(|e| {
                    error!("Failed to suspend the target: {}", e);
                    "Failed to suspend the target"
                })?;
                return Ok(StopReason::GdbInterrupt);
            }
        }
    }

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
    ) -> TargetResult<(), Self> {
        match self.vcpu_request(VcpuControl::Debug(VcpuDebug::ReadMem(
            GuestAddress(start_addr),
            data.len(),
        ))) {
            Ok(VcpuDebugStatus::MemoryRegion(r)) => {
                for (dst, v) in data.iter_mut().zip(r.iter()) {
                    *dst = *v;
                }
                Ok(())
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
}

impl Breakpoints for GdbStub {
    fn hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
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
        // If we already have 4 breakpoints, we cannot set a new one.
        if self.hw_breakpoints.len() >= 4 {
            error!("Not allowed to set more than 4 HW breakpoints");
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

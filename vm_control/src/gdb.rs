// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use gdbstub::arch::Arch;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
#[cfg(target_arch = "riscv64")]
use gdbstub_arch::riscv::Riscv64 as GdbArch;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbArch;
use vm_memory::GuestAddress;

/// Messages that can be sent to a vCPU to set/get its state from the debugger.
#[derive(Clone, Debug)]
pub enum VcpuDebug {
    ReadMem(GuestAddress, usize),
    ReadRegs,
    ReadReg(<GdbArch as Arch>::RegId),
    WriteRegs(Box<<GdbArch as Arch>::Registers>),
    WriteReg(<GdbArch as Arch>::RegId, Vec<u8>),
    WriteMem(GuestAddress, Vec<u8>),
    EnableSinglestep,
    GetHwBreakPointCount,
    SetHwBreakPoint(Vec<GuestAddress>),
}

/// Messages that can be sent from a vCPU to update the state to the debugger.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VcpuDebugStatus {
    RegValues(<GdbArch as Arch>::Registers),
    RegValue(Vec<u8>),
    MemoryRegion(Vec<u8>),
    CommandComplete,
    HwBreakPointCount(usize),
    HitBreakPoint,
}

/// Pair of a vCPU ID and messages that can be sent from the vCPU to update the state to the
/// debugger.
#[derive(Debug)]
pub struct VcpuDebugStatusMessage {
    pub cpu: usize,
    pub msg: VcpuDebugStatus,
}

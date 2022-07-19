// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use gdbstub::arch::Arch;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbArch;
use vm_memory::GuestAddress;

/// Messages that can be sent to a vCPU to set/get its state from the debugger.
#[derive(Clone, Debug)]
pub enum VcpuDebug {
    ReadMem(GuestAddress, usize),
    ReadRegs,
    WriteRegs(Box<<GdbArch as Arch>::Registers>),
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

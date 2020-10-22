// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_arch = "x86_64")]
use gdbstub::arch::x86::reg::X86_64CoreRegs as CoreRegs;
use vm_memory::GuestAddress;

/// Messages that can be sent to a vCPU to set/get its state from the debugger.
#[derive(Debug)]
pub enum VcpuDebug {
    ReadMem(GuestAddress, usize),
    ReadRegs,
    WriteRegs(Box<CoreRegs>),
    WriteMem(GuestAddress, Vec<u8>),
    EnableSinglestep,
    SetHwBreakPoint(Vec<GuestAddress>),
}

/// Messages that can be sent from a vCPU to update the state to the debugger.
#[derive(Debug)]
pub enum VcpuDebugStatus {
    RegValues(CoreRegs),
    MemoryRegion(Vec<u8>),
    CommandComplete,
    HitBreakPoint,
}

/// Pair of a vCPU ID and messages that can be sent from the vCPU to update the state to the
/// debugger.
#[derive(Debug)]
pub struct VcpuDebugStatusMessage {
    pub cpu: usize,
    pub msg: VcpuDebugStatus,
}

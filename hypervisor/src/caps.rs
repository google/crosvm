// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// An enumeration of different hypervisor capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypervisorCap {
    ArmPmuV3,
    ImmediateExit,
    S390UserSigp,
    TscDeadlineTimer,
    UserMemory,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Xcrs,
}

/// A capability the `Vm` can possibly expose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmCap {
    /// Track dirty pages
    DirtyLog,
    /// Paravirtualized clock device
    PvClock,
    /// PV clock can be notified when guest is being paused
    PvClockSuspend,
    /// VM can be run in protected mode, where the host does not have access to its memory.
    Protected,
}

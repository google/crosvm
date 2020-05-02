// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::Result;

use crate::{Hypervisor, Vcpu, Vm};

/// A trait for managing cpuids for an x86_64 hypervisor and for checking its capabilities.
pub trait HypervisorX86_64: Hypervisor {
    /// Get the system supported CPUID values.
    fn get_supported_cpuid(&self) -> Result<CpuId>;

    /// Get the system emulated CPUID values.
    fn get_emulated_cpuid(&self) -> Result<CpuId>;
}

/// A wrapper for using a VM on x86_64 and getting/setting its state.
pub trait VmX86_64: Vm {
    type Vcpu: VcpuX86_64;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu>;
}

/// A wrapper around creating and using a VCPU on x86_64.
pub trait VcpuX86_64: Vcpu {
    /// Gets the VCPU registers.
    fn get_regs(&self) -> Result<Regs>;
}

/// A CpuId Entry contains supported feature information for the given processor.
/// This can be modified by the hypervisor to pass additional information to the guest kernel
/// about the hypervisor or vm. Information is returned in the eax, ebx, ecx and edx registers
/// by the cpu for a given function and index/subfunction (passed into the cpu via the eax and ecx
/// register respectively).
pub struct CpuIdEntry {
    pub function: u32,
    pub index: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// A container for the list of cpu id entries for the hypervisor and underlying cpu.
pub struct CpuId {
    pub cpu_id_entries: Vec<CpuIdEntry>,
}

/// The state of a vcpu's general-purpose registers.
pub struct Regs {}

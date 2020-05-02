// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use kvm_sys::kvm_cpuid_entry2;
use sys_util::Result;

use crate::{Hypervisor, Vcpu, Vm};

pub type CpuIdEntry = kvm_cpuid_entry2;

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

pub struct CpuId {
    _cpu_id_entries: Vec<CpuIdEntry>,
}

/// The state of a vcpu's general-purpose registers.
pub struct Regs {}

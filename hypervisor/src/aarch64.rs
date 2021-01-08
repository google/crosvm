// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Result;
use downcast_rs::impl_downcast;
use vm_memory::GuestAddress;

use crate::{Hypervisor, IrqRoute, IrqSource, IrqSourceChip, Vcpu, Vm};

/// Represents a version of Power State Coordination Interface (PSCI).
pub struct PsciVersion {
    pub major: u32,
    pub minor: u32,
}

/// A wrapper for using a VM on aarch64 and getting/setting its state.
pub trait VmAArch64: Vm {
    /// Gets the `Hypervisor` that created this VM.
    fn get_hypervisor(&self) -> &dyn Hypervisor;

    /// Enables protected mode for the VM, creating a memslot for the firmware as needed.
    /// Only works on VMs that support `VmCap::Protected`.
    fn enable_protected_vm(&mut self, fw_addr: GuestAddress, fw_max_size: u64) -> Result<()>;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>>;
}

/// A wrapper around creating and using a VCPU on aarch64.
pub trait VcpuAArch64: Vcpu {
    /// Does ARM-specific initialization of this VCPU.  Inits the VCPU with the preferred target
    /// VCPU type and the specified `features`, and resets the value of all registers to defaults.
    /// All VCPUs should be created before calling this function.
    fn init(&self, features: &[VcpuFeature]) -> Result<()>;

    /// Initializes the ARM Performance Monitor Unit v3 on this VCPU, with overflow interrupt number
    /// `irq`.
    fn init_pmu(&self, irq: u64) -> Result<()>;

    /// Sets the value of a register on this VCPU.  `reg_id` is the register ID, as specified in the
    /// KVM API documentation for KVM_SET_ONE_REG.
    fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()>;

    /// Gets the value of a register on this VCPU.  `reg_id` is the register ID, as specified in the
    /// KVM API documentation for KVM_GET_ONE_REG.
    fn get_one_reg(&self, reg_id: u64) -> Result<u64>;

    /// Gets the current PSCI version.
    fn get_psci_version(&self) -> Result<PsciVersion>;
}

impl_downcast!(VcpuAArch64);

// Convenience constructors for IrqRoutes
impl IrqRoute {
    pub fn gic_irq_route(irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Gic,
                pin: irq_num,
            },
        }
    }
}

/// A feature that can be enabled on a VCPU with `VcpuAArch64::init`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuFeature {
    /// Emulate PSCI v0.2 (or a future revision backward compatible with v0.2) for the VCPU.
    PsciV0_2,
    /// Emulate Performance Monitor Unit v3 for the VCPU.
    PmuV3,
    /// Starts the VCPU in a power-off state.
    PowerOff,
}

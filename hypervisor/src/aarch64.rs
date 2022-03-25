// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;

use base::{Error, Result};
use downcast_rs::impl_downcast;
use libc::EINVAL;
use vm_memory::GuestAddress;

use crate::{Hypervisor, IrqRoute, IrqSource, IrqSourceChip, Vcpu, Vm};

/// Represents a version of Power State Coordination Interface (PSCI).
#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub struct PsciVersion {
    pub major: u16,
    pub minor: u16,
}

impl PsciVersion {
    pub fn new(major: u16, minor: u16) -> Result<Self> {
        if (major as i16) < 0 {
            Err(Error::new(EINVAL))
        } else {
            Ok(Self { major, minor })
        }
    }
}

impl TryFrom<u32> for PsciVersion {
    type Error = base::Error;

    fn try_from(item: u32) -> Result<Self> {
        Self::new((item >> 16) as u16, item as u16)
    }
}

pub const PSCI_0_2: PsciVersion = PsciVersion { major: 0, minor: 2 };
pub const PSCI_1_0: PsciVersion = PsciVersion { major: 1, minor: 0 };

/// A wrapper for using a VM on aarch64 and getting/setting its state.
pub trait VmAArch64: Vm {
    /// Gets the `Hypervisor` that created this VM.
    fn get_hypervisor(&self) -> &dyn Hypervisor;

    /// Load pVM firmware for the VM, creating a memslot for it as needed.
    ///
    /// Only works on protected VMs (i.e. those  that support `VmCap::Protected`).
    fn load_protected_vm_firmware(&mut self, fw_addr: GuestAddress, fw_max_size: u64)
        -> Result<()>;

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

    /// Checks if ARM ParaVirtualized Time is supported on this VCPU
    fn has_pvtime_support(&self) -> bool;

    /// Initializes the ARM ParaVirtualized Time on this VCPU, with base address of the stolen time
    /// structure as `pvtime_ipa`.
    fn init_pvtime(&self, pvtime_ipa: u64) -> Result<()>;

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

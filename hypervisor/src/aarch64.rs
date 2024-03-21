// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryFrom;

use anyhow::anyhow;
use base::Error;
use base::Result;
use cros_fdt::Fdt;
use downcast_rs::impl_downcast;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
use libc::EINVAL;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;

use crate::Hypervisor;
use crate::IrqRoute;
use crate::IrqSource;
use crate::IrqSourceChip;
use crate::Vcpu;
use crate::Vm;

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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum VcpuRegAArch64 {
    X(u8),
    Sp,
    Pc,
    Pstate,
}

/// A wrapper for using a VM on aarch64 and getting/setting its state.
pub trait VmAArch64: Vm {
    /// Gets the `Hypervisor` that created this VM.
    fn get_hypervisor(&self) -> &dyn Hypervisor;

    /// Load pVM firmware for the VM, creating a memslot for it as needed.
    ///
    /// Only works on protected VMs (i.e. those that support `VmCap::Protected`).
    fn load_protected_vm_firmware(&mut self, fw_addr: GuestAddress, fw_max_size: u64)
        -> Result<()>;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>>;

    /// Create DT configuration node for the hypervisor.
    /// `fdt` - Fdt initialized at the root node.
    /// `phandles` - Map of strings to a phandle.
    fn create_fdt(&self, fdt: &mut Fdt, phandles: &BTreeMap<&str, u32>) -> cros_fdt::Result<()>;

    // Initialize a VM. Called after building the VM. Presently called before vCPUs are initialized.
    fn init_arch(
        &self,
        payload_entry_address: GuestAddress,
        fdt_address: GuestAddress,
        fdt_size: usize,
    ) -> Result<()>;
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

    /// Sets the value of a register on this VCPU.
    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()>;

    /// Gets the value of a register on this VCPU.
    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64>;

    /// Gets the value of MPIDR_EL1 on this VCPU.
    fn get_mpidr(&self) -> Result<u64> {
        const RES1: u64 = 1 << 31;

        // Assume that MPIDR_EL1.{U,MT} = {0,0}.

        let aff = u64::try_from(self.id()).unwrap();

        Ok(RES1 | aff)
    }

    /// Gets the current PSCI version.
    fn get_psci_version(&self) -> Result<PsciVersion>;

    #[cfg(feature = "gdb")]
    /// Sets up debug registers and configure vcpu for handling guest debug events.
    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()>;

    #[cfg(feature = "gdb")]
    /// Sets the VCPU general registers used by GDB 'G' packets.
    fn set_gdb_registers(&self, regs: &<GdbArch as Arch>::Registers) -> Result<()>;

    #[cfg(feature = "gdb")]
    /// Gets the VCPU general registers used by GDB 'g' packets.
    fn get_gdb_registers(&self, regs: &mut <GdbArch as Arch>::Registers) -> Result<()>;

    #[cfg(feature = "gdb")]
    /// Gets the max number of hardware breakpoints.
    fn get_max_hw_bps(&self) -> Result<usize>;

    #[cfg(feature = "gdb")]
    /// Sets the value of a single register on this VCPU.
    fn set_gdb_register(&self, reg: <GdbArch as Arch>::RegId, data: &[u8]) -> Result<()>;

    #[cfg(feature = "gdb")]
    /// Gets the value of a single register on this VCPU.
    fn get_gdb_register(&self, reg: <GdbArch as Arch>::RegId, data: &mut [u8]) -> Result<usize>;

    /// Snapshot VCPU
    fn snapshot(&self) -> anyhow::Result<VcpuSnapshot> {
        Err(anyhow!("not yet implemented"))
    }

    /// Restore VCPU
    fn restore(&self, _snapshot: &VcpuSnapshot) -> anyhow::Result<()> {
        Err(anyhow!("not yet implemented"))
    }
}

/// Aarch64 specific vCPU snapshot.
///
/// Not implemented yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuSnapshot {
    pub vcpu_id: usize,
}

impl_downcast!(VcpuAArch64);

/// Initial register state for AArch64 VCPUs.
#[derive(Clone, Default)]
pub struct VcpuInitAArch64 {
    /// Initial register state as a map of register name to value pairs. Registers that do not have
    /// a value specified in this map will retain the original value provided by the hypervisor.
    pub regs: BTreeMap<VcpuRegAArch64, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuConfigAArch64 {}

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

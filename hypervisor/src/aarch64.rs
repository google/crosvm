// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;

use aarch64_sys_reg::AArch64SysRegId;
use anyhow::Context;
use base::Error;
use base::Result;
use cros_fdt::Fdt;
use downcast_rs::impl_downcast;
use libc::EINVAL;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
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

// Aarch64 does not provide a concrete number as to how many registers exist.
// The list of registers available exceeds 600 registers
pub const AARCH64_MAX_REG_COUNT: usize = 1024;

pub const PSCI_0_2: PsciVersion = PsciVersion { major: 0, minor: 2 };
pub const PSCI_1_0: PsciVersion = PsciVersion { major: 1, minor: 0 };

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum VcpuRegAArch64 {
    X(u8),
    Sp,
    Pc,
    Pstate,
    System(AArch64SysRegId),
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
    ) -> anyhow::Result<()>;

    /// Set an offset that describes a number of counter cycles that are subtracted from both
    /// virtual and physical counter views.
    fn set_counter_offset(&self, _offset: u64) -> Result<()> {
        Err(Error::new(libc::ENOSYS))
    }
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

    /// Sets the value of a Neon vector register (V0-V31) on this VCPU.
    fn set_vector_reg(&self, reg_num: u8, data: u128) -> Result<()>;

    /// Gets the value of a Neon vector register (V0-V31) on this VCPU.
    fn get_vector_reg(&self, reg_num: u8) -> Result<u128>;

    /// Gets the set of system registers accessible by the hypervisor
    fn get_system_regs(&self) -> Result<BTreeMap<AArch64SysRegId, u64>>;

    /// Gets the hypervisor specific data for snapshot
    fn hypervisor_specific_snapshot(&self) -> anyhow::Result<AnySnapshot>;

    /// Restores the hypervisor specific data
    fn hypervisor_specific_restore(&self, _data: AnySnapshot) -> anyhow::Result<()>;

    /// Gets the value of MPIDR_EL1 on this VCPU.
    fn get_mpidr(&self) -> Result<u64> {
        const RES1: u64 = 1 << 31;

        // Assume that MPIDR_EL1.{U,MT} = {0,0}.

        let aff = u64::try_from(self.id()).unwrap();

        Ok(RES1 | aff)
    }

    /// Gets the current PSCI version.
    fn get_psci_version(&self) -> Result<PsciVersion>;

    /// Sets up debug registers and configure vcpu for handling guest debug events.
    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()>;

    /// Gets the max number of hardware breakpoints.
    fn get_max_hw_bps(&self) -> Result<usize>;

    /// Gets the cache architecture information for all cache levels.
    /// The keys of the map are the lower 4 lower significant bits of CSSELR_EL1, which represents
    /// the cache level. cache level is actually located in bits [3:1], but the value saves also
    /// if the cache is an instruction or data.
    /// The values of the map are CCSIDR_EL1, which is the configuration of the cache.
    fn get_cache_info(&self) -> Result<BTreeMap<u8, u64>>;

    /// Sets the cache architecture information for all cache levels.
    fn set_cache_info(&self, cache_info: BTreeMap<u8, u64>) -> Result<()>;

    fn snapshot(&self) -> anyhow::Result<VcpuSnapshot> {
        let mut snap = VcpuSnapshot {
            vcpu_id: self.id(),
            sp: self
                .get_one_reg(VcpuRegAArch64::Sp)
                .context("Failed to get SP")?,
            pc: self
                .get_one_reg(VcpuRegAArch64::Pc)
                .context("Failed to get PC")?,
            pstate: self
                .get_one_reg(VcpuRegAArch64::Pstate)
                .context("Failed to get PState")?,
            x: Default::default(),
            v: Default::default(),
            hypervisor_data: self
                .hypervisor_specific_snapshot()
                .context("Failed to get hyprevisor specific data")?,
            sys: self
                .get_system_regs()
                .context("Failed to read system registers")?,
            cache_arch_info: self.get_cache_info().context("Failed to get cache info")?,
        };

        for (n, xn) in snap.x.iter_mut().enumerate() {
            *xn = self
                .get_one_reg(VcpuRegAArch64::X(n as u8))
                .with_context(|| format!("Failed to get X{}", n))?;
        }

        for (n, vn) in snap.v.iter_mut().enumerate() {
            *vn = self
                .get_vector_reg(n as u8)
                .with_context(|| format!("Failed to get V{}", n))?;
        }

        Ok(snap)
    }

    /// Restore VCPU
    fn restore(&self, snapshot: &VcpuSnapshot) -> anyhow::Result<()> {
        self.set_one_reg(VcpuRegAArch64::Sp, snapshot.sp)
            .context("Failed to restore SP register")?;
        self.set_one_reg(VcpuRegAArch64::Pc, snapshot.pc)
            .context("Failed to restore PC register")?;
        self.set_one_reg(VcpuRegAArch64::Pstate, snapshot.pstate)
            .context("Failed to restore PState register")?;

        for (n, xn) in snapshot.x.iter().enumerate() {
            self.set_one_reg(VcpuRegAArch64::X(n as u8), *xn)
                .with_context(|| format!("Failed to restore X{}", n))?;
        }
        for (n, vn) in snapshot.v.iter().enumerate() {
            self.set_vector_reg(n as u8, *vn)
                .with_context(|| format!("Failed to restore V{}", n))?;
        }
        for (id, val) in &snapshot.sys {
            self.set_one_reg(VcpuRegAArch64::System(*id), *val)
                .with_context(|| format!("Failed to restore system register {:?}", id))?;
        }
        self.set_cache_info(snapshot.cache_arch_info.clone())
            .context("Failed to restore cache info")?;
        self.hypervisor_specific_restore(snapshot.hypervisor_data.clone())
            .context("Failed to restore hypervisor specific data")?;
        Ok(())
    }
}

/// Aarch64 specific vCPU snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuSnapshot {
    pub vcpu_id: usize,
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub x: [u64; 31],
    pub v: [u128; 32],
    pub sys: BTreeMap<AArch64SysRegId, u64>,
    pub cache_arch_info: BTreeMap<u8, u64>,
    pub hypervisor_data: AnySnapshot,
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
    /// Scalable Vector Extension support
    Sve,
}

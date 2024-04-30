// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;

use anyhow::anyhow;
use base::Error;
use base::Result;
use cros_fdt::Fdt;
use downcast_rs::impl_downcast;
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

/// AArch64 system register as used in MSR/MRS instructions.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AArch64SysRegId(u16);

impl AArch64SysRegId {
    /// Construct a system register ID from Op0, Op1, CRn, CRm, Op2.
    ///
    /// The meanings of the arguments are described in the ARMv8 Architecture Reference Manual
    /// "System instruction class encoding overview" section.
    pub fn new(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Result<Self> {
        if op0 > 0b11 || op1 > 0b111 || crn > 0b1111 || crm > 0b1111 || op2 > 0b111 {
            return Err(Error::new(EINVAL));
        }

        Ok(Self::new_unchecked(op0, op1, crn, crm, op2))
    }

    /// Construct a system register ID from Op0, Op1, CRn, CRm, Op2.
    ///
    /// Out-of-range values will be silently truncated.
    pub const fn new_unchecked(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> Self {
        let op0 = (op0 as u16 & 0b11) << 14;
        let op1 = (op1 as u16 & 0b111) << 11;
        let crn = (crn as u16 & 0b1111) << 7;
        let crm = (crm as u16 & 0b1111) << 3;
        let op2 = op2 as u16 & 0b111;
        Self(op0 | op1 | crn | crm | op2)
    }

    pub fn from_encoded(v: u16) -> Self {
        Self(v)
    }

    #[inline]
    pub const fn op0(&self) -> u8 {
        ((self.0 >> 14) & 0b11) as u8
    }

    #[inline]
    pub const fn op1(&self) -> u8 {
        ((self.0 >> 11) & 0b111) as u8
    }

    #[inline]
    pub const fn crn(&self) -> u8 {
        ((self.0 >> 7) & 0b1111) as u8
    }

    #[inline]
    pub const fn crm(&self) -> u8 {
        ((self.0 >> 3) & 0b1111) as u8
    }

    #[inline]
    pub const fn op2(&self) -> u8 {
        (self.0 & 0b111) as u8
    }

    /// Returns the system register as encoded in bits 5-20 of MRS and MSR instructions.
    pub const fn encoded(&self) -> u16 {
        self.0
    }
}

impl Debug for AArch64SysRegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AArch64SysRegId")
            .field("Op0", &self.op0())
            .field("Op1", &self.op1())
            .field("CRn", &self.crn())
            .field("CRm", &self.crm())
            .field("Op2", &self.op2())
            .finish()
    }
}

#[rustfmt::skip]
#[allow(non_upper_case_globals)]
impl AArch64SysRegId {
    //                                                         Op0    Op1     CRn     CRm    Op2
    pub const MPIDR_EL1: Self           = Self::new_unchecked(0b11, 0b000, 0b0000, 0b0000, 0b101);
    pub const CCSIDR_EL1: Self          = Self::new_unchecked(0b11, 0b001, 0b0000, 0b0000, 0b000);
    pub const CSSELR_EL1: Self          = Self::new_unchecked(0b11, 0b010, 0b0000, 0b0000, 0b000);
    pub const FPCR: Self                = Self::new_unchecked(0b11, 0b011, 0b0100, 0b0100, 0b000);
    pub const FPSR: Self                = Self::new_unchecked(0b11, 0b011, 0b0100, 0b0100, 0b001);
    pub const SPSR_EL1: Self            = Self::new_unchecked(0b11, 0b000, 0b0100, 0b0000, 0b000);
    pub const SPSR_irq: Self            = Self::new_unchecked(0b11, 0b100, 0b0100, 0b0011, 0b000);
    pub const SPSR_abt: Self            = Self::new_unchecked(0b11, 0b100, 0b0100, 0b0011, 0b001);
    pub const SPSR_und: Self            = Self::new_unchecked(0b11, 0b100, 0b0100, 0b0011, 0b010);
    pub const SPSR_fiq: Self            = Self::new_unchecked(0b11, 0b100, 0b0100, 0b0011, 0b011);
    pub const ELR_EL1: Self             = Self::new_unchecked(0b11, 0b000, 0b0100, 0b0000, 0b001);
    pub const SP_EL1: Self              = Self::new_unchecked(0b11, 0b100, 0b0100, 0b0001, 0b000);
    pub const CNTVCT_EL0: Self          = Self::new_unchecked(0b11, 0b011, 0b1110, 0b0000, 0b010);
    pub const CNTV_CVAL_EL0: Self       = Self::new_unchecked(0b11, 0b011, 0b1110, 0b0011, 0b010);
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
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

    /// Sets the value of a Neon vector register (V0-V31) on this VCPU.
    fn set_vector_reg(&self, reg_num: u8, data: u128) -> Result<()>;

    /// Gets the value of a Neon vector register (V0-V31) on this VCPU.
    fn get_vector_reg(&self, reg_num: u8) -> Result<u128>;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysreg_new() {
        let sysreg = AArch64SysRegId::new(1, 2, 3, 4, 5).unwrap();
        assert_eq!(sysreg.op0(), 1);
        assert_eq!(sysreg.op1(), 2);
        assert_eq!(sysreg.crn(), 3);
        assert_eq!(sysreg.crm(), 4);
        assert_eq!(sysreg.op2(), 5);
        assert_eq!(sysreg.encoded(), 0x51A5);
    }

    #[test]
    fn sysreg_new_max() {
        let sysreg = AArch64SysRegId::new(0b11, 0b111, 0b1111, 0b1111, 0b111).unwrap();
        assert_eq!(sysreg.op0(), 3);
        assert_eq!(sysreg.op1(), 7);
        assert_eq!(sysreg.crn(), 15);
        assert_eq!(sysreg.crm(), 15);
        assert_eq!(sysreg.op2(), 7);
        assert_eq!(sysreg.encoded(), 0xFFFF);
    }

    #[test]
    fn sysreg_new_out_of_range() {
        AArch64SysRegId::new(4, 0, 0, 0, 0).expect_err("invalid Op0");
        AArch64SysRegId::new(0, 8, 0, 0, 0).expect_err("invalid Op1");
        AArch64SysRegId::new(0, 0, 16, 0, 0).expect_err("invalid CRn");
        AArch64SysRegId::new(0, 0, 0, 16, 0).expect_err("invalid CRm");
        AArch64SysRegId::new(0, 0, 0, 0, 8).expect_err("invalid Op2");
    }

    #[test]
    fn sysreg_encoding_mpidr_el1() {
        assert_eq!(AArch64SysRegId::MPIDR_EL1.op0(), 3);
        assert_eq!(AArch64SysRegId::MPIDR_EL1.op1(), 0);
        assert_eq!(AArch64SysRegId::MPIDR_EL1.crn(), 0);
        assert_eq!(AArch64SysRegId::MPIDR_EL1.crm(), 0);
        assert_eq!(AArch64SysRegId::MPIDR_EL1.op2(), 5);
        assert_eq!(AArch64SysRegId::MPIDR_EL1.encoded(), 0xC005);
        assert_eq!(
            AArch64SysRegId::MPIDR_EL1,
            AArch64SysRegId::new(3, 0, 0, 0, 5).unwrap()
        );
    }

    #[test]
    fn sysreg_encoding_cntvct_el0() {
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.op0(), 3);
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.op1(), 3);
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.crn(), 14);
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.crm(), 0);
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.op2(), 2);
        assert_eq!(AArch64SysRegId::CNTVCT_EL0.encoded(), 0xDF02);
        assert_eq!(
            AArch64SysRegId::CNTVCT_EL0,
            AArch64SysRegId::new(3, 3, 14, 0, 2).unwrap()
        );
    }

    #[test]
    fn sysreg_encoding_cntv_cval_el0() {
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.op0(), 3);
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.op1(), 3);
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.crn(), 14);
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.crm(), 3);
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.op2(), 2);
        assert_eq!(AArch64SysRegId::CNTV_CVAL_EL0.encoded(), 0xDF1A);
        assert_eq!(
            AArch64SysRegId::CNTV_CVAL_EL0,
            AArch64SysRegId::new(3, 3, 14, 3, 2).unwrap()
        );
    }

    #[test]
    fn sysreg_debug() {
        assert_eq!(
            format!("{:?}", AArch64SysRegId::MPIDR_EL1),
            "AArch64SysRegId { Op0: 3, Op1: 0, CRn: 0, CRm: 0, Op2: 5 }"
        );
    }
}

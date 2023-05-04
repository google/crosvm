// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::errno_result;
use base::error;
use base::ioctl_with_ref;
use base::Error;
use base::Result;
use kvm_sys::*;
use libc::ENXIO;

use super::Config;
use super::Kvm;
use super::KvmVcpu;
use super::KvmVm;
use crate::ClockState;
use crate::DeviceKind;
use crate::Hypervisor;
use crate::IrqSourceChip;
use crate::ProtectionType;
use crate::VcpuExit;
use crate::VcpuRegister;
use crate::VcpuRiscv64;
use crate::VmCap;
use crate::VmRiscv64;

impl KvmVm {
    /// Does platform specific initialization for the KvmVm.
    pub fn init_arch(&self, _cfg: &Config) -> Result<()> {
        Ok(())
    }

    /// Checks if a particular `VmCap` is available, or returns None if arch-independent
    /// Vm.check_capability() should handle the check.
    pub fn check_capability_arch(&self, _c: VmCap) -> Option<bool> {
        None
    }

    /// Returns the params to pass to KVM_CREATE_DEVICE for a `kind` device on this arch, or None to
    /// let the arch-independent `KvmVm::create_device` handle it.
    pub fn get_device_params_arch(&self, kind: DeviceKind) -> Option<kvm_create_device> {
        match kind {
            DeviceKind::RiscvAia => Some(kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
                fd: 0,
                flags: 0,
            }),
            _ => None,
        }
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.  Always returns an error on riscv64.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        Err(Error::new(ENXIO))
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.  Always returns an error on riscv64.
    pub fn set_pvclock_arch(&self, _state: &ClockState) -> Result<()> {
        Err(Error::new(ENXIO))
    }
}

impl Kvm {
    // The riscv machine type is always 0. Protected VMs are not supported, yet.
    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        if protection_type == ProtectionType::Unprotected {
            Ok(0)
        } else {
            error!("Protected mode is not supported on riscv64.");
            Err(Error::new(libc::EINVAL))
        }
    }

    /// Get the size of guest physical addresses in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // assume sv48 addressing
        48
    }
}

impl VmRiscv64 for KvmVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.kvm
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuRiscv64>> {
        // create_vcpu is declared separately for each arch so it can return the arch-apropriate
        // vcpu type. But all use the same implementation in KvmVm::create_vcpu.
        Ok(Box::new(self.create_kvm_vcpu(id)?))
    }
}

impl KvmVcpu {
    /// Arch-specific implementation of `Vcpu::pvclock_ctrl`.  Always returns an error on Riscv64.
    pub fn pvclock_ctrl_arch(&self) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    /// Handles a `KVM_EXIT_SYSTEM_EVENT` with event type `KVM_SYSTEM_EVENT_RESET` with the given
    /// event flags and returns the appropriate `VcpuExit` value for the run loop to handle.
    ///
    /// `event_flags` should be one or more of the `KVM_SYSTEM_EVENT_RESET_FLAG_*` values defined by
    /// KVM.
    pub fn system_event_reset(&self, _event_flags: u64) -> Result<VcpuExit> {
        Ok(VcpuExit::SystemEventReset)
    }
}

impl VcpuRiscv64 for KvmVcpu {
    fn set_one_reg(&self, reg: VcpuRegister, data: u64) -> Result<()> {
        let data_ref = &data as *const u64;
        let onereg = kvm_one_reg {
            id: vcpu_reg_id(reg),
            addr: data_ref as u64,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG(), &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_one_reg(&self, reg: VcpuRegister) -> Result<u64> {
        let val: u64 = 0;
        let onereg = kvm_one_reg {
            id: vcpu_reg_id(reg),
            addr: (&val as *const u64) as u64,
        };

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_ONE_REG(), &onereg) };
        if ret == 0 {
            Ok(val)
        } else {
            errno_result()
        }
    }
}

// Returns the id used for call to `KVM_[GET|SET]_ONE_REG`.
fn vcpu_reg_id(reg: VcpuRegister) -> u64 {
    fn id_from_reg(reg_type: u32, index: u64) -> u64 {
        reg_type as u64 | index | KVM_REG_RISCV as u64 | KVM_REG_SIZE_U64 as u64
    }

    match reg {
        VcpuRegister::Config(r) => id_from_reg(KVM_REG_RISCV_CONFIG, r as u64),
        VcpuRegister::Core(r) => id_from_reg(KVM_REG_RISCV_CORE, r as u64),
        VcpuRegister::Timer(r) => id_from_reg(KVM_REG_RISCV_TIMER, r as u64),
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between the architectures because the irqchip KVM constants are not defined on all
// of them.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        // Riscv does not have a constant for this, but the default routing
        // setup seems to set this to 0
        IrqSourceChip::Aia => 0,
        _ => {
            error!("Invalid IrqChipSource for Riscv {:?}", chip);
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreRegister;

    #[test]
    fn reg_id() {
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Pc)),
            0x8030_0000_0200_0000
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Ra)),
            0x8030_0000_0200_0001
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Sp)),
            0x8030_0000_0200_0002
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Gp)),
            0x8030_0000_0200_0003
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Tp)),
            0x8030_0000_0200_0004
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T0)),
            0x8030_0000_0200_0005
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T1)),
            0x8030_0000_0200_0006
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T2)),
            0x8030_0000_0200_0007
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S0)),
            0x8030_0000_0200_0008
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S1)),
            0x8030_0000_0200_0009
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A0)),
            0x8030_0000_0200_000a
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A1)),
            0x8030_0000_0200_000b
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A2)),
            0x8030_0000_0200_000c
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A3)),
            0x8030_0000_0200_000d
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A4)),
            0x8030_0000_0200_000e
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A5)),
            0x8030_0000_0200_000f
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A6)),
            0x8030_0000_0200_0010
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::A7)),
            0x8030_0000_0200_0011
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S2)),
            0x8030_0000_0200_0012
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S3)),
            0x8030_0000_0200_0013
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S4)),
            0x8030_0000_0200_0014
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S5)),
            0x8030_0000_0200_0015
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S6)),
            0x8030_0000_0200_0016
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S7)),
            0x8030_0000_0200_0017
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S8)),
            0x8030_0000_0200_0018
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S9)),
            0x8030_0000_0200_0019
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S10)),
            0x8030_0000_0200_001a
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::S11)),
            0x8030_0000_0200_001b
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T3)),
            0x8030_0000_0200_001c
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T4)),
            0x8030_0000_0200_001d
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T5)),
            0x8030_0000_0200_001e
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::T6)),
            0x8030_0000_0200_001f
        );
        assert_eq!(
            vcpu_reg_id(VcpuRegister::Core(CoreRegister::Mode)),
            0x8030_0000_0200_0020
        );
    }
}

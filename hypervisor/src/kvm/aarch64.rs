// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// We have u32 constants from bindings that are passed into archiitecture-dependent functions
// taking u32/64 parameters. So on 32 bit platforms we may have needless casts.
#![allow(clippy::useless_conversion)]

use std::convert::TryFrom;

use base::errno_result;
use base::error;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::warn;
use base::Error;
use base::Result;
#[cfg(feature = "gdb")]
use gdbstub::arch::Arch;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::reg::id::AArch64RegId;
#[cfg(feature = "gdb")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
use kvm_sys::*;
use libc::EINVAL;
#[cfg(feature = "gdb")]
use libc::ENOBUFS;
#[cfg(feature = "gdb")]
use libc::ENOENT;
use libc::ENOMEM;
use libc::ENOTSUP;
#[cfg(feature = "gdb")]
use libc::ENOTUNIQ;
use libc::ENXIO;
use vm_memory::GuestAddress;

use super::Config;
use super::Kvm;
use super::KvmCap;
use super::KvmVcpu;
use super::KvmVm;
use crate::ClockState;
use crate::DeviceKind;
use crate::Hypervisor;
use crate::IrqSourceChip;
use crate::ProtectionType;
use crate::PsciVersion;
use crate::VcpuAArch64;
use crate::VcpuExit;
use crate::VcpuFeature;
use crate::VcpuRegAArch64;
use crate::VmAArch64;
use crate::VmCap;
use crate::PSCI_0_2;

impl Kvm {
    // Compute the machine type, which should be the IPA range for the VM
    // Ideally, this would take a description of the memory map and return
    // the closest machine type for this VM. Here, we just return the maximum
    // the kernel support.
    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        // Safe because we know self is a real kvm fd
        let ipa_size = match unsafe {
            ioctl_with_val(self, KVM_CHECK_EXTENSION(), KVM_CAP_ARM_VM_IPA_SIZE.into())
        } {
            // Not supported? Use 0 as the machine type, which implies 40bit IPA
            ret if ret < 0 => 0,
            ipa => ipa as u32,
        };
        let protection_flag = if protection_type.isolates_memory() {
            KVM_VM_TYPE_ARM_PROTECTED
        } else {
            0
        };
        // Use the lower 8 bits representing the IPA space as the machine type
        Ok((ipa_size & KVM_VM_TYPE_ARM_IPA_SIZE_MASK) | protection_flag)
    }

    /// Get the size of guest physical addresses (IPA) in bits.
    pub fn get_guest_phys_addr_bits(&self) -> u8 {
        // Safe because we know self is a real kvm fd
        match unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), KVM_CAP_ARM_VM_IPA_SIZE.into()) }
        {
            // Default physical address size is 40 bits if the extension is not supported.
            ret if ret <= 0 => 40,
            ipa => ipa as u8,
        }
    }
}

impl KvmVm {
    /// Does platform specific initialization for the KvmVm.
    pub fn init_arch(&self, cfg: &Config) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        if cfg.mte {
            // Safe because it does not take pointer arguments.
            unsafe { self.enable_raw_capability(KvmCap::ArmMte, 0, &[0, 0, 0, 0])? }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // Suppress warning.
            let _ = cfg;
        }

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
            DeviceKind::ArmVgicV2 => Some(kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
                fd: 0,
                flags: 0,
            }),
            DeviceKind::ArmVgicV3 => Some(kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
                fd: 0,
                flags: 0,
            }),
            _ => None,
        }
    }

    /// Arch-specific implementation of `Vm::get_pvclock`.  Always returns an error on AArch64.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        Err(Error::new(ENXIO))
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.  Always returns an error on AArch64.
    pub fn set_pvclock_arch(&self, _state: &ClockState) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    fn get_protected_vm_info(&self) -> Result<KvmProtectedVmInfo> {
        let mut info = KvmProtectedVmInfo {
            firmware_size: 0,
            reserved: [0; 7],
        };
        // Safe because we allocated the struct and we know the kernel won't write beyond the end of
        // the struct or keep a pointer to it.
        unsafe {
            self.enable_raw_capability(
                KvmCap::ArmProtectedVm,
                KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO,
                &[&mut info as *mut KvmProtectedVmInfo as u64, 0, 0, 0],
            )
        }?;
        Ok(info)
    }

    fn set_protected_vm_firmware_ipa(&self, fw_addr: GuestAddress) -> Result<()> {
        // Safe because none of the args are pointers.
        unsafe {
            self.enable_raw_capability(
                KvmCap::ArmProtectedVm,
                KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA,
                &[fw_addr.0, 0, 0, 0],
            )
        }
    }

    /// Enable userspace msr. This is not available on ARM, just succeed.
    pub fn enable_userspace_msr(&self) -> Result<()> {
        Ok(())
    }
}

#[repr(C)]
struct KvmProtectedVmInfo {
    firmware_size: u64,
    reserved: [u64; 7],
}

impl VmAArch64 for KvmVm {
    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.kvm
    }

    fn load_protected_vm_firmware(
        &mut self,
        fw_addr: GuestAddress,
        fw_max_size: u64,
    ) -> Result<()> {
        let info = self.get_protected_vm_info()?;
        if info.firmware_size == 0 {
            Err(Error::new(EINVAL))
        } else {
            if info.firmware_size > fw_max_size {
                return Err(Error::new(ENOMEM));
            }
            self.set_protected_vm_firmware_ipa(fw_addr)
        }
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>> {
        // create_vcpu is declared separately in VmAArch64 and VmX86, so it can return VcpuAArch64
        // or VcpuX86.  But both use the same implementation in KvmVm::create_kvm_vcpu.
        Ok(Box::new(self.create_kvm_vcpu(id)?))
    }
}

impl KvmVcpu {
    /// Arch-specific implementation of `Vcpu::pvclock_ctrl`.  Always returns an error on AArch64.
    pub fn pvclock_ctrl_arch(&self) -> Result<()> {
        Err(Error::new(ENXIO))
    }

    /// Handles a `KVM_EXIT_SYSTEM_EVENT` with event type `KVM_SYSTEM_EVENT_RESET` with the given
    /// event flags and returns the appropriate `VcpuExit` value for the run loop to handle.
    ///
    /// `event_flags` should be one or more of the `KVM_SYSTEM_EVENT_RESET_FLAG_*` values defined by
    /// KVM.
    pub fn system_event_reset(&self, event_flags: u64) -> Result<VcpuExit> {
        if event_flags & KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2 != 0 {
            // Read reset_type and cookie from x1 and x2.
            let reset_type = self.get_one_reg(VcpuRegAArch64::X(1))?;
            let cookie = self.get_one_reg(VcpuRegAArch64::X(2))?;
            warn!(
                "PSCI SYSTEM_RESET2 with reset_type={:#x}, cookie={:#x}",
                reset_type, cookie
            );
        }
        Ok(VcpuExit::SystemEventReset)
    }

    fn set_one_kvm_reg_u64(&self, kvm_reg_id: KvmVcpuRegister, data: u64) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_kvm_reg(&self, kvm_reg_id: KvmVcpuRegister, data: &[u8]) -> Result<()> {
        let onereg = kvm_one_reg {
            id: kvm_reg_id.into(),
            addr: (data.as_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
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

    fn get_one_kvm_reg_u64(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u64> {
        let mut bytes = 0u64.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn get_one_kvm_reg(&self, kvm_reg_id: KvmVcpuRegister, data: &mut [u8]) -> Result<()> {
        let onereg = kvm_one_reg {
            id: kvm_reg_id.into(),
            addr: (data.as_mut_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_ONE_REG(), &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

#[cfg(feature = "gdb")]
impl KvmVcpu {
    fn set_one_kvm_reg_u32(&self, kvm_reg_id: KvmVcpuRegister, data: u32) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_kvm_reg_u128(&self, kvm_reg_id: KvmVcpuRegister, data: u128) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn get_one_kvm_reg_u32(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u32> {
        let mut bytes = 0u32.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn get_one_kvm_reg_u128(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u128> {
        let mut bytes = 0u128.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u128::from_ne_bytes(bytes))
    }

    /// Retrieves the value of the currently active "version" of a multiplexed registers.
    fn demux_register(&self, reg: &<GdbArch as Arch>::RegId) -> Result<Option<KvmVcpuRegister>> {
        match *reg {
            AArch64RegId::CCSIDR_EL1 => {
                let csselr = KvmVcpuRegister::try_from(AArch64RegId::CSSELR_EL1)
                    .expect("can't map AArch64RegId::CSSELR_EL1 to KvmVcpuRegister");
                if let Ok(csselr) = self.get_one_kvm_reg_u64(csselr) {
                    Ok(Some(KvmVcpuRegister::Ccsidr(csselr as u8)))
                } else {
                    Ok(None)
                }
            }
            _ => {
                error!("Register {:?} is not multiplexed", reg);
                Err(Error::new(EINVAL))
            }
        }
    }
}

#[allow(dead_code)]
/// KVM registers as used by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API
///
/// These variants represent the registers as exposed by KVM which must be different from
/// `VcpuRegAArch64` to support registers which don't have an architectural definition such as
/// pseudo-registers (`Firmware`) and multiplexed registers (`Ccsidr`).
///
/// See https://docs.kernel.org/virt/kvm/api.html for more details.
pub enum KvmVcpuRegister {
    /// General Purpose Registers X0-X30
    X(u8),
    /// Stack Pointer
    Sp,
    /// Program Counter
    Pc,
    /// Processor State
    Pstate,
    /// Stack Pointer (EL1)
    SpEl1,
    /// Exception Link Register (EL1)
    ElrEl1,
    /// Saved Program Status Register (EL1, abt, und, irq, fiq)
    Spsr(u8),
    /// FP & SIMD Registers V0-V31
    V(u8),
    /// Floating-point Status Register
    Fpsr,
    /// Floating-point Control Register
    Fpcr,
    /// KVM Firmware Pseudo-Registers
    Firmware(u16),
    /// Generic System Registers by (Op0, Op1, CRn, CRm, Op2)
    System(u16),
    /// CCSIDR_EL1 Demultiplexed by CSSELR_EL1
    Ccsidr(u8),
}

impl KvmVcpuRegister {
    // Firmware pseudo-registers are part of the ARM KVM interface:
    //     https://docs.kernel.org/virt/kvm/arm/hypercalls.html
    pub const PSCI_VERSION: Self = Self::Firmware(0);
    pub const SMCCC_ARCH_WORKAROUND_1: Self = Self::Firmware(1);
    pub const SMCCC_ARCH_WORKAROUND_2: Self = Self::Firmware(2);
    pub const SMCCC_ARCH_WORKAROUND_3: Self = Self::Firmware(3);
}

/// Gives the `u64` register ID expected by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API.
///
/// See the KVM documentation of those ioctls for details about the format of the register ID.
impl From<KvmVcpuRegister> for u64 {
    fn from(register: KvmVcpuRegister) -> Self {
        const fn reg(size: u64, kind: u64, fields: u64) -> u64 {
            KVM_REG_ARM64 | size | kind | fields
        }

        const fn kvm_regs_reg(size: u64, offset: usize) -> u64 {
            let offset = offset / std::mem::size_of::<u32>();

            reg(size, KVM_REG_ARM_CORE as u64, offset as u64)
        }

        const fn kvm_reg(offset: usize) -> u64 {
            kvm_regs_reg(KVM_REG_SIZE_U64, offset)
        }

        fn user_pt_reg(offset: usize) -> u64 {
            kvm_regs_reg(
                KVM_REG_SIZE_U64,
                memoffset::offset_of!(kvm_regs, regs) + offset,
            )
        }

        fn user_fpsimd_state_reg(size: u64, offset: usize) -> u64 {
            kvm_regs_reg(size, memoffset::offset_of!(kvm_regs, fp_regs) + offset)
        }

        const fn reg_u64(kind: u64, fields: u64) -> u64 {
            reg(KVM_REG_SIZE_U64, kind, fields)
        }

        const fn demux_reg(size: u64, index: u64, value: u64) -> u64 {
            let index = (index << KVM_REG_ARM_DEMUX_ID_SHIFT) & (KVM_REG_ARM_DEMUX_ID_MASK as u64);
            let value =
                (value << KVM_REG_ARM_DEMUX_VAL_SHIFT) & (KVM_REG_ARM_DEMUX_VAL_MASK as u64);

            reg(size, KVM_REG_ARM_DEMUX as u64, index | value)
        }

        match register {
            KvmVcpuRegister::X(n @ 0..=30) => {
                let n = std::mem::size_of::<u64>() * (n as usize);

                user_pt_reg(memoffset::offset_of!(user_pt_regs, regs) + n)
            }
            KvmVcpuRegister::X(n) => unreachable!("invalid KvmVcpuRegister Xn index: {n}"),
            KvmVcpuRegister::Sp => user_pt_reg(memoffset::offset_of!(user_pt_regs, sp)),
            KvmVcpuRegister::Pc => user_pt_reg(memoffset::offset_of!(user_pt_regs, pc)),
            KvmVcpuRegister::Pstate => user_pt_reg(memoffset::offset_of!(user_pt_regs, pstate)),
            KvmVcpuRegister::SpEl1 => kvm_reg(memoffset::offset_of!(kvm_regs, sp_el1)),
            KvmVcpuRegister::ElrEl1 => kvm_reg(memoffset::offset_of!(kvm_regs, elr_el1)),
            KvmVcpuRegister::Spsr(n @ 0..=4) => {
                let n = std::mem::size_of::<u64>() * (n as usize);

                kvm_reg(memoffset::offset_of!(kvm_regs, spsr) + n)
            }
            KvmVcpuRegister::Spsr(n) => unreachable!("invalid KvmVcpuRegister Spsr index: {n}"),
            KvmVcpuRegister::V(n @ 0..=31) => {
                let n = std::mem::size_of::<u128>() * (n as usize);

                user_fpsimd_state_reg(
                    KVM_REG_SIZE_U128,
                    memoffset::offset_of!(user_fpsimd_state, vregs) + n,
                )
            }
            KvmVcpuRegister::V(n) => unreachable!("invalid KvmVcpuRegister Vn index: {n}"),
            KvmVcpuRegister::Fpsr => user_fpsimd_state_reg(
                KVM_REG_SIZE_U32,
                memoffset::offset_of!(user_fpsimd_state, fpsr),
            ),
            KvmVcpuRegister::Fpcr => user_fpsimd_state_reg(
                KVM_REG_SIZE_U32,
                memoffset::offset_of!(user_fpsimd_state, fpcr),
            ),
            KvmVcpuRegister::Firmware(n) => reg_u64(KVM_REG_ARM_FW.into(), n.into()),
            KvmVcpuRegister::System(n) => reg_u64(KVM_REG_ARM64_SYSREG.into(), n.into()),
            KvmVcpuRegister::Ccsidr(n) => demux_reg(KVM_REG_SIZE_U32, 0, n.into()),
        }
    }
}

#[cfg(feature = "gdb")]
/// Returns whether KVM matches more than one KVM_GET_ONE_REG target to the given arch register.
const fn kvm_multiplexes(reg: &<GdbArch as Arch>::RegId) -> bool {
    matches!(*reg, AArch64RegId::CCSIDR_EL1)
}

#[cfg(feature = "gdb")]
impl TryFrom<AArch64RegId> for KvmVcpuRegister {
    type Error = Error;

    fn try_from(reg: <GdbArch as Arch>::RegId) -> std::result::Result<Self, Self::Error> {
        if kvm_multiplexes(&reg) {
            // Many-to-one mapping between the register and its KVM_GET_ONE_REG values.
            error!(
                "Can't map multiplexed register {:?} to unique KVM value",
                reg
            );
            return Err(Error::new(ENOTUNIQ));
        }

        let kvm_reg = match reg {
            AArch64RegId::X(n @ 0..=30) => Self::X(n),
            AArch64RegId::X(n) => unreachable!("invalid AArch64RegId Xn index: {n}"),
            AArch64RegId::V(n @ 0..=31) => Self::V(n),
            AArch64RegId::V(n) => unreachable!("invalid AArch64RegId Vn index: {n}"),
            AArch64RegId::Sp => Self::Sp,
            AArch64RegId::Pc => Self::Pc,
            AArch64RegId::Pstate => Self::Pstate,
            AArch64RegId::ELR_EL1 => Self::ElrEl1,
            AArch64RegId::SP_EL1 => Self::SpEl1,
            AArch64RegId::SPSR_EL1 => Self::Spsr(KVM_SPSR_EL1 as u8),
            AArch64RegId::SPSR_ABT => Self::Spsr(KVM_SPSR_ABT as u8),
            AArch64RegId::SPSR_UND => Self::Spsr(KVM_SPSR_UND as u8),
            AArch64RegId::SPSR_IRQ => Self::Spsr(KVM_SPSR_IRQ as u8),
            AArch64RegId::SPSR_FIQ => Self::Spsr(KVM_SPSR_FIQ as u8),
            AArch64RegId::FPSR => Self::Fpsr,
            AArch64RegId::FPCR => Self::Fpcr,
            // The KVM API accidentally swapped CNTV_CVAL_EL0 and CNTVCT_EL0
            AArch64RegId::CNTV_CVAL_EL0 => match AArch64RegId::CNTVCT_EL0 {
                AArch64RegId::System(op) => Self::System(op),
                _ => unreachable!("AArch64RegId::CNTVCT_EL0 not a AArch64RegId::System"),
            },
            AArch64RegId::CNTVCT_EL0 => match AArch64RegId::CNTV_CVAL_EL0 {
                AArch64RegId::System(op) => Self::System(op),
                _ => unreachable!("AArch64RegId::CNTV_CVAL_EL0 not a AArch64RegId::System"),
            },
            AArch64RegId::System(op) => Self::System(op),
            _ => {
                error!("Unexpected AArch64RegId: {:?}", reg);
                return Err(Error::new(EINVAL));
            }
        };

        Ok(kvm_reg)
    }
}

impl From<VcpuRegAArch64> for KvmVcpuRegister {
    fn from(reg: VcpuRegAArch64) -> Self {
        match reg {
            VcpuRegAArch64::X(n @ 0..=30) => Self::X(n),
            VcpuRegAArch64::X(n) => unreachable!("invalid VcpuRegAArch64 index: {n}"),
            VcpuRegAArch64::Sp => Self::Sp,
            VcpuRegAArch64::Pc => Self::Pc,
            VcpuRegAArch64::Pstate => Self::Pstate,
        }
    }
}

impl VcpuAArch64 for KvmVcpu {
    fn init(&self, features: &[VcpuFeature]) -> Result<()> {
        let mut kvi = kvm_vcpu_init {
            target: KVM_ARM_TARGET_GENERIC_V8,
            features: [0; 7],
        };
        // Safe because we allocated the struct and we know the kernel will write exactly the size
        // of the struct.
        let ret = unsafe { ioctl_with_mut_ref(&self.vm, KVM_ARM_PREFERRED_TARGET(), &mut kvi) };
        if ret != 0 {
            return errno_result();
        }

        for f in features {
            let shift = match f {
                VcpuFeature::PsciV0_2 => KVM_ARM_VCPU_PSCI_0_2,
                VcpuFeature::PmuV3 => KVM_ARM_VCPU_PMU_V3,
                VcpuFeature::PowerOff => KVM_ARM_VCPU_POWER_OFF,
            };
            kvi.features[0] |= 1 << shift;
        }

        // Safe because we know self.vm is a real kvm fd
        let check_extension = |ext: u32| -> bool {
            unsafe { ioctl_with_val(&self.vm, KVM_CHECK_EXTENSION(), ext.into()) == 1 }
        };
        if check_extension(KVM_CAP_ARM_PTRAUTH_ADDRESS)
            && check_extension(KVM_CAP_ARM_PTRAUTH_GENERIC)
        {
            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
            kvi.features[0] |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        }

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT(), &kvi) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn init_pmu(&self, irq: u64) -> Result<()> {
        let irq_addr = &irq as *const u64;

        // The in-kernel PMU virtualization is initialized by setting the irq
        // with KVM_ARM_VCPU_PMU_V3_IRQ and then by KVM_ARM_VCPU_PMU_V3_INIT.

        let irq_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: KVM_ARM_VCPU_PMU_V3_IRQ as u64,
            addr: irq_addr as u64,
            flags: 0,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_HAS_DEVICE_ATTR(), &irq_attr) };
        if ret < 0 {
            return errno_result();
        }

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR(), &irq_attr) };
        if ret < 0 {
            return errno_result();
        }

        let init_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: KVM_ARM_VCPU_PMU_V3_INIT as u64,
            addr: 0,
            flags: 0,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR(), &init_attr) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    fn has_pvtime_support(&self) -> bool {
        // The in-kernel PV time structure is initialized by setting the base
        // address with KVM_ARM_VCPU_PVTIME_IPA
        let pvtime_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PVTIME_CTRL,
            attr: KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: 0,
            flags: 0,
        };
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_HAS_DEVICE_ATTR(), &pvtime_attr) };
        ret >= 0
    }

    fn init_pvtime(&self, pvtime_ipa: u64) -> Result<()> {
        let pvtime_ipa_addr = &pvtime_ipa as *const u64;

        // The in-kernel PV time structure is initialized by setting the base
        // address with KVM_ARM_VCPU_PVTIME_IPA
        let pvtime_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PVTIME_CTRL,
            attr: KVM_ARM_VCPU_PVTIME_IPA as u64,
            addr: pvtime_ipa_addr as u64,
            flags: 0,
        };

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR(), &pvtime_attr) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()> {
        self.set_one_kvm_reg_u64(KvmVcpuRegister::from(reg_id), data)
    }

    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64> {
        self.get_one_kvm_reg_u64(KvmVcpuRegister::from(reg_id))
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        let version = if let Ok(v) = self.get_one_kvm_reg_u64(KvmVcpuRegister::PSCI_VERSION) {
            let v = u32::try_from(v).map_err(|_| Error::new(EINVAL))?;
            PsciVersion::try_from(v)?
        } else {
            // When `KVM_REG_ARM_PSCI_VERSION` is not supported, we can return PSCI 0.2, as vCPU
            // has been initialized with `KVM_ARM_VCPU_PSCI_0_2` successfully.
            PSCI_0_2
        };

        if version < PSCI_0_2 {
            // PSCI v0.1 isn't currently supported for guests
            Err(Error::new(ENOTSUP))
        } else {
            Ok(version)
        }
    }

    #[cfg(feature = "gdb")]
    fn get_max_hw_bps(&self) -> Result<usize> {
        // Safe because the kernel will only return the result of the ioctl.
        let max_hw_bps = unsafe {
            ioctl_with_val(
                &self.vm,
                KVM_CHECK_EXTENSION(),
                KVM_CAP_GUEST_DEBUG_HW_BPS.into(),
            )
        };

        if max_hw_bps < 0 {
            errno_result()
        } else {
            Ok(max_hw_bps.try_into().expect("can't represent u64 as usize"))
        }
    }

    #[cfg(feature = "gdb")]
    #[allow(clippy::unusual_byte_groupings)]
    fn set_guest_debug(&self, addrs: &[GuestAddress], enable_singlestep: bool) -> Result<()> {
        let mut dbg = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE,
            ..Default::default()
        };

        if enable_singlestep {
            dbg.control |= KVM_GUESTDBG_SINGLESTEP;
        }
        if !addrs.is_empty() {
            dbg.control |= KVM_GUESTDBG_USE_HW;
        }

        for (i, guest_addr) in addrs.iter().enumerate() {
            // From the ARMv8 Architecture Reference Manual (DDI0487H.a) D31.3.{2,3}:
            // When DBGBCR<n>_EL1.BT == 0b000x:
            //      DBGBVR<n>_EL1, Bits [1:0]: Reserved, RES0
            if guest_addr.0 & 0b11 != 0 {
                return Err(Error::new(EINVAL));
            }
            let sign_ext = 15;
            //      DBGBVR<n>_EL1.RESS[14:0], bits [63:49]: Reserved, Sign extended
            dbg.arch.dbg_bvr[i] = (((guest_addr.0 << sign_ext) as i64) >> sign_ext) as u64;
            // DBGBCR<n>_EL1.BT, bits [23:20]: Breakpoint Type
            //      0b0000: Unlinked instruction address match.
            //              DBGBVR<n>_EL1 is the address of an instruction.
            // DBGBCR<n>_EL1.BAS, bits [8:5]: Byte address select
            //      0b1111: Use for A64 and A32 instructions
            // DBGBCR<n>_EL1.PMC, bits [2:1]: Privilege mode control
            //      0b11: EL1 & EL0
            // DBGBCR<n>_EL1.E, bit [0]: Enable breakpoint
            //      0b1: Enabled
            dbg.arch.dbg_bcr[i] = 0b1111_11_1;
        }

        // Safe because the kernel won't read past the end of the kvm_guest_debug struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GUEST_DEBUG(), &dbg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_registers(&self, regs: &<GdbArch as Arch>::Registers) -> Result<()> {
        assert!(
            regs.x.len() == 31,
            "unexpected number of Xn general purpose registers"
        );
        for (i, reg) in regs.x.iter().enumerate() {
            let n = u8::try_from(i).expect("invalid Xn general purpose register index");
            self.set_one_kvm_reg_u64(KvmVcpuRegister::X(n), *reg)?;
        }
        self.set_one_kvm_reg_u64(KvmVcpuRegister::Sp, regs.sp)?;
        self.set_one_kvm_reg_u64(KvmVcpuRegister::Pc, regs.pc)?;
        // GDB gives a 32-bit value for "CPSR" but KVM wants a 64-bit Pstate.
        let pstate = self.get_one_kvm_reg_u64(KvmVcpuRegister::Pstate)?;
        let pstate = (pstate & 0xffff_ffff_0000_0000) | (regs.cpsr as u64);
        self.set_one_kvm_reg_u64(KvmVcpuRegister::Pstate, pstate)?;
        for (i, reg) in regs.v.iter().enumerate() {
            let n = u8::try_from(i).expect("invalid Vn general purpose register index");
            self.set_one_kvm_reg_u128(KvmVcpuRegister::V(n), *reg)?;
        }
        self.set_one_kvm_reg_u32(KvmVcpuRegister::Fpcr, regs.fpcr)?;
        self.set_one_kvm_reg_u32(KvmVcpuRegister::Fpsr, regs.fpsr)?;

        Ok(())
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_registers(&self, regs: &mut <GdbArch as Arch>::Registers) -> Result<()> {
        assert!(
            regs.x.len() == 31,
            "unexpected number of Xn general purpose registers"
        );
        for (i, reg) in regs.x.iter_mut().enumerate() {
            let n = u8::try_from(i).expect("invalid Xn general purpose register index");
            *reg = self.get_one_kvm_reg_u64(KvmVcpuRegister::X(n))?;
        }
        regs.sp = self.get_one_kvm_reg_u64(KvmVcpuRegister::Sp)?;
        regs.pc = self.get_one_kvm_reg_u64(KvmVcpuRegister::Pc)?;
        // KVM gives a 64-bit value for Pstate but GDB wants a 32-bit "CPSR".
        regs.cpsr = self.get_one_kvm_reg_u64(KvmVcpuRegister::Pstate)? as u32;
        for (i, reg) in regs.v.iter_mut().enumerate() {
            let n = u8::try_from(i).expect("invalid Vn general purpose register index");
            *reg = self.get_one_kvm_reg_u128(KvmVcpuRegister::V(n))?;
        }
        regs.fpcr = self.get_one_kvm_reg_u32(KvmVcpuRegister::Fpcr)?;
        regs.fpsr = self.get_one_kvm_reg_u32(KvmVcpuRegister::Fpsr)?;

        Ok(())
    }

    #[cfg(feature = "gdb")]
    fn set_gdb_register(&self, reg: <GdbArch as Arch>::RegId, data: &[u8]) -> Result<()> {
        let len = reg.len().ok_or(Error::new(EINVAL))?;
        if data.len() < len {
            return Err(Error::new(ENOBUFS));
        }
        let kvm_reg = if kvm_multiplexes(&reg) {
            self.demux_register(&reg)?.ok_or(Error::new(ENOENT))?
        } else {
            KvmVcpuRegister::try_from(reg)?
        };
        self.set_one_kvm_reg(kvm_reg, &data[..len])
    }

    #[cfg(feature = "gdb")]
    fn get_gdb_register(&self, reg: <GdbArch as Arch>::RegId, data: &mut [u8]) -> Result<usize> {
        let len = reg.len().ok_or(Error::new(EINVAL))?;
        if data.len() < len {
            return Err(Error::new(ENOBUFS));
        }
        let kvm_reg = if !kvm_multiplexes(&reg) {
            KvmVcpuRegister::try_from(reg)?
        } else if let Some(r) = self.demux_register(&reg)? {
            r
        } else {
            return Ok(0); // Unavailable register
        };

        self.get_one_kvm_reg(kvm_reg, &mut data[..len])
            .and(Ok(len))
            // ENOENT is returned when KVM is aware of the register but it is unavailable
            .or_else(|e| if e.errno() == ENOENT { Ok(0) } else { Err(e) })
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between x86_64 and aarch64 because the irqchip KVM constants are not defined on
// all architectures.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        // ARM does not have a constant for this, but the default routing
        // setup seems to set this to 0
        IrqSourceChip::Gic => 0,
        _ => {
            error!("Invalid IrqChipSource for ARM {:?}", chip);
            0
        }
    }
}

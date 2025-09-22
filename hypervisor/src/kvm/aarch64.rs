// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// We have u32 constants from bindings that are passed into archiitecture-dependent functions
// taking u32/64 parameters. So on 32 bit platforms we may have needless casts.
#![allow(clippy::useless_conversion)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::mem::offset_of;

use aarch64_sys_reg::AArch64SysRegId;
use anyhow::Context;
use base::errno_result;
use base::error;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ref;
use base::ioctl_with_val;
use base::warn;
use base::Error;
use base::Result;
use cros_fdt::Fdt;
use data_model::vec_with_array_field;
use kvm_sys::*;
use libc::EINVAL;
use libc::ENOMEM;
use libc::ENOTSUP;
use libc::ENXIO;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
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
use crate::AARCH64_MAX_REG_COUNT;
use crate::PSCI_0_2;

impl Kvm {
    // Compute the machine type, which should be the IPA range for the VM
    // Ideally, this would take a description of the memory map and return
    // the closest machine type for this VM. Here, we just return the maximum
    // the kernel support.
    pub fn get_vm_type(&self, protection_type: ProtectionType) -> Result<u32> {
        // SAFETY:
        // Safe because we know self is a real kvm fd
        let ipa_size = match unsafe {
            ioctl_with_val(self, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE.into())
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
        // SAFETY:
        // Safe because we know self is a real kvm fd
        match unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE.into()) } {
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
            // SAFETY:
            // Safe because it does not take pointer arguments.
            unsafe { self.enable_raw_capability(KvmCap::ArmMte, 0, &[0, 0, 0, 0])? }
        }
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        if cfg.ffa {
            self.set_enable_ffa(true)?;
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
            DeviceKind::ArmVgicIts => Some(kvm_create_device {
                type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
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

    /// Get pKVM hypervisor details, e.g. the firmware size.
    ///
    /// Returns `Err` if not running under pKVM.
    ///
    /// Uses `KVM_ENABLE_CAP` internally, but it is only a getter, there should be no side effects
    /// in KVM.
    fn get_protected_vm_info(&self) -> Result<KvmProtectedVmInfo> {
        let mut info = KvmProtectedVmInfo {
            firmware_size: 0,
            reserved: [0; 7],
        };
        // SAFETY:
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
        // SAFETY:
        // Safe because none of the args are pointers.
        unsafe {
            self.enable_raw_capability(
                KvmCap::ArmProtectedVm,
                KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FW_IPA,
                &[fw_addr.0, 0, 0, 0],
            )
        }
    }

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    fn set_enable_ffa(&self, ffa_support: bool) -> Result<()> {
        // SAFETY:
        // Safe because none of the args are pointers.
        unsafe {
            self.enable_raw_capability(
                KvmCap::ArmProtectedVm,
                KVM_CAP_ARM_PROTECTED_VM_FLAGS_SET_FFA,
                &[ffa_support.into(), 0, 0, 0],
            )
        }
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

    fn create_fdt(&self, _fdt: &mut Fdt, _phandles: &BTreeMap<&str, u32>) -> cros_fdt::Result<()> {
        Ok(())
    }

    fn init_arch(
        &self,
        _payload_entry_address: GuestAddress,
        _fdt_address: GuestAddress,
        _fdt_size: usize,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn set_counter_offset(&self, offset: u64) -> Result<()> {
        let off = kvm_arm_counter_offset {
            counter_offset: offset,
            reserved: 0,
        };
        // SAFETY: self.vm is a valid KVM fd
        let ret = unsafe { ioctl_with_ref(&self.vm, KVM_ARM_SET_COUNTER_OFFSET, &off) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }
}

impl KvmVcpu {
    /// Handles a `KVM_EXIT_SYSTEM_EVENT` with event type `KVM_SYSTEM_EVENT_RESET` with the given
    /// event flags and returns the appropriate `VcpuExit` value for the run loop to handle.
    ///
    /// `event_flags` should be one or more of the `KVM_SYSTEM_EVENT_RESET_FLAG_*` values defined by
    /// KVM.
    pub fn system_event_reset(&self, event_flags: u64) -> Result<VcpuExit> {
        if event_flags & u64::from(KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2) != 0 {
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

    fn kvm_reg_id(&self, reg: VcpuRegAArch64) -> Result<KvmVcpuRegister> {
        match reg {
            VcpuRegAArch64::X(n @ 0..=30) => Ok(KvmVcpuRegister::X(n)),
            VcpuRegAArch64::Sp => Ok(KvmVcpuRegister::Sp),
            VcpuRegAArch64::Pc => Ok(KvmVcpuRegister::Pc),
            VcpuRegAArch64::Pstate => Ok(KvmVcpuRegister::Pstate),
            // Special case for multiplexed KVM registers
            VcpuRegAArch64::System(aarch64_sys_reg::CCSIDR_EL1) => {
                let csselr =
                    self.get_one_reg(VcpuRegAArch64::System(aarch64_sys_reg::CSSELR_EL1))?;
                Ok(KvmVcpuRegister::Ccsidr(csselr as u8))
            }
            VcpuRegAArch64::System(sysreg) => Ok(KvmVcpuRegister::System(sysreg)),
            _ => Err(Error::new(EINVAL)),
        }
    }

    fn set_one_kvm_reg_u32(&self, kvm_reg_id: KvmVcpuRegister, data: u32) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_kvm_reg_u64(&self, kvm_reg_id: KvmVcpuRegister, data: u64) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_kvm_reg_u128(&self, kvm_reg_id: KvmVcpuRegister, data: u128) -> Result<()> {
        self.set_one_kvm_reg(kvm_reg_id, data.to_ne_bytes().as_slice())
    }

    fn set_one_kvm_reg(&self, kvm_reg_id: KvmVcpuRegister, data: &[u8]) -> Result<()> {
        assert_eq!(kvm_reg_id.size(), data.len());
        let id: u64 = kvm_reg_id.into();
        let onereg = kvm_one_reg {
            id,
            addr: (data.as_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_ONE_REG, &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    fn get_one_kvm_reg_u32(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u32> {
        let mut bytes = 0u32.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn get_one_kvm_reg_u64(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u64> {
        let mut bytes = 0u64.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn get_one_kvm_reg_u128(&self, kvm_reg_id: KvmVcpuRegister) -> Result<u128> {
        let mut bytes = 0u128.to_ne_bytes();
        self.get_one_kvm_reg(kvm_reg_id, bytes.as_mut_slice())?;
        Ok(u128::from_ne_bytes(bytes))
    }

    fn get_one_kvm_reg(&self, kvm_reg_id: KvmVcpuRegister, data: &mut [u8]) -> Result<()> {
        assert_eq!(kvm_reg_id.size(), data.len());
        let id: u64 = kvm_reg_id.into();
        let onereg = kvm_one_reg {
            id,
            addr: (data.as_mut_ptr() as usize)
                .try_into()
                .expect("can't represent usize as u64"),
        };

        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_ONE_REG, &onereg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }

    #[inline]
    pub(crate) fn handle_vm_exit_arch(&self, _run: &mut kvm_run) -> Option<VcpuExit> {
        // No aarch64-specific exits (for now)
        None
    }

    fn get_reg_list(&self) -> Result<Vec<u64>> {
        let mut kvm_reg_list = vec_with_array_field::<kvm_reg_list, u64>(AARCH64_MAX_REG_COUNT);
        kvm_reg_list[0].n = AARCH64_MAX_REG_COUNT as u64;
        let ret =
            // SAFETY:
            // We trust the kernel not to read/write past the end of kvm_reg_list struct.
            unsafe { ioctl_with_mut_ref(self, KVM_GET_REG_LIST, &mut kvm_reg_list[0]) };
        if ret < 0 {
            return errno_result();
        }
        let n = kvm_reg_list[0].n;
        assert!(
            n <= AARCH64_MAX_REG_COUNT as u64,
            "Get reg list returned more registers than possible"
        );
        // SAFETY:
        // Mapping the unsized array to a slice is unsafe because the length isn't known.
        // Providing the length used to create the struct guarantees the entire slice is valid.
        let reg_list: &[u64] = unsafe { kvm_reg_list[0].reg.as_slice(n as usize) };
        Ok(reg_list.to_vec())
    }

    fn get_features_bitmap(&self, features: &[VcpuFeature]) -> Result<u32> {
        let mut all_features = 0;
        let check_extension = |ext: u32| -> bool {
            // SAFETY:
            // Safe because we know self.vm is a real kvm fd
            unsafe { ioctl_with_val(&self.vm, KVM_CHECK_EXTENSION, ext.into()) == 1 }
        };

        for f in features {
            let shift = match f {
                VcpuFeature::PsciV0_2 => KVM_ARM_VCPU_PSCI_0_2,
                VcpuFeature::PmuV3 => KVM_ARM_VCPU_PMU_V3,
                VcpuFeature::PowerOff => KVM_ARM_VCPU_POWER_OFF,
                VcpuFeature::Sve => {
                    if !check_extension(KVM_CAP_ARM_SVE) {
                        return Err(Error::new(ENOTSUP));
                    }
                    KVM_ARM_VCPU_SVE
                }
            };
            all_features |= 1 << shift;
        }

        if check_extension(KVM_CAP_ARM_PTRAUTH_ADDRESS)
            && check_extension(KVM_CAP_ARM_PTRAUTH_GENERIC)
        {
            all_features |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
            all_features |= 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        }

        Ok(all_features)
    }

    /// Finalize VCPU features setup. This does not affect features that do not make use of
    /// finalize.
    fn finalize(&self, features: u32) -> Result<()> {
        if (features & 1 << KVM_ARM_VCPU_SVE) != 0 {
            // SAFETY:
            // Safe because we know that our file is a Vcpu fd and we verify the return result.
            let ret = unsafe {
                ioctl_with_ref(
                    self,
                    KVM_ARM_VCPU_FINALIZE,
                    &std::os::raw::c_int::try_from(KVM_ARM_VCPU_SVE)
                        .map_err(|_| Error::new(EINVAL))?,
                )
            };
            if ret != 0 {
                return errno_result();
            }
        }

        Ok(())
    }
}

/// KVM registers as used by the `GET_ONE_REG`/`SET_ONE_REG` ioctl API
///
/// These variants represent the registers as exposed by KVM which must be different from
/// `VcpuRegAArch64` to support registers which don't have an architectural definition such as
/// pseudo-registers (`Firmware`) and multiplexed registers (`Ccsidr`).
///
/// See https://docs.kernel.org/virt/kvm/api.html for more details.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum KvmVcpuRegister {
    /// General Purpose Registers X0-X30
    X(u8),
    /// Stack Pointer
    Sp,
    /// Program Counter
    Pc,
    /// Processor State
    Pstate,
    /// FP & SIMD Registers V0-V31
    V(u8),
    /// KVM Firmware Pseudo-Registers
    Firmware(u16),
    /// System Registers
    System(AArch64SysRegId),
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

    /// Size of this register in bytes.
    pub fn size(&self) -> usize {
        let kvm_reg = u64::from(*self);
        let size_field = kvm_reg & KVM_REG_SIZE_MASK;
        const REG_SIZE_U8: u64 = KVM_REG_SIZE_U8 as u64; // cast from bindgen's u32 to u64
        match size_field {
            REG_SIZE_U8 => 1,
            KVM_REG_SIZE_U16 => 2,
            KVM_REG_SIZE_U32 => 4,
            KVM_REG_SIZE_U64 => 8,
            KVM_REG_SIZE_U128 => 16,
            KVM_REG_SIZE_U256 => 32,
            KVM_REG_SIZE_U512 => 64,
            KVM_REG_SIZE_U1024 => 128,
            KVM_REG_SIZE_U2048 => 256,
            // `From<KvmVcpuRegister> for u64` should always include a valid size.
            _ => panic!("invalid size field {}", size_field),
        }
    }
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

        fn spsr_reg(spsr_reg: u32) -> u64 {
            let n = std::mem::size_of::<u64>() * (spsr_reg as usize);
            kvm_reg(offset_of!(kvm_regs, spsr) + n)
        }

        fn user_pt_reg(offset: usize) -> u64 {
            kvm_regs_reg(KVM_REG_SIZE_U64, offset_of!(kvm_regs, regs) + offset)
        }

        fn user_fpsimd_state_reg(size: u64, offset: usize) -> u64 {
            kvm_regs_reg(size, offset_of!(kvm_regs, fp_regs) + offset)
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

                user_pt_reg(offset_of!(user_pt_regs, regs) + n)
            }
            KvmVcpuRegister::X(n) => unreachable!("invalid KvmVcpuRegister Xn index: {n}"),
            KvmVcpuRegister::Sp => user_pt_reg(offset_of!(user_pt_regs, sp)),
            KvmVcpuRegister::Pc => user_pt_reg(offset_of!(user_pt_regs, pc)),
            KvmVcpuRegister::Pstate => user_pt_reg(offset_of!(user_pt_regs, pstate)),
            KvmVcpuRegister::V(n @ 0..=31) => {
                let n = std::mem::size_of::<u128>() * (n as usize);

                user_fpsimd_state_reg(KVM_REG_SIZE_U128, offset_of!(user_fpsimd_state, vregs) + n)
            }
            KvmVcpuRegister::V(n) => unreachable!("invalid KvmVcpuRegister Vn index: {n}"),
            KvmVcpuRegister::System(aarch64_sys_reg::FPSR) => {
                user_fpsimd_state_reg(KVM_REG_SIZE_U32, offset_of!(user_fpsimd_state, fpsr))
            }
            KvmVcpuRegister::System(aarch64_sys_reg::FPCR) => {
                user_fpsimd_state_reg(KVM_REG_SIZE_U32, offset_of!(user_fpsimd_state, fpcr))
            }
            KvmVcpuRegister::System(aarch64_sys_reg::SPSR_EL1) => spsr_reg(KVM_SPSR_EL1),
            KvmVcpuRegister::System(aarch64_sys_reg::SPSR_abt) => spsr_reg(KVM_SPSR_ABT),
            KvmVcpuRegister::System(aarch64_sys_reg::SPSR_und) => spsr_reg(KVM_SPSR_UND),
            KvmVcpuRegister::System(aarch64_sys_reg::SPSR_irq) => spsr_reg(KVM_SPSR_IRQ),
            KvmVcpuRegister::System(aarch64_sys_reg::SPSR_fiq) => spsr_reg(KVM_SPSR_FIQ),
            KvmVcpuRegister::System(aarch64_sys_reg::SP_EL1) => {
                kvm_reg(offset_of!(kvm_regs, sp_el1))
            }
            KvmVcpuRegister::System(aarch64_sys_reg::ELR_EL1) => {
                kvm_reg(offset_of!(kvm_regs, elr_el1))
            }
            // The KVM API accidentally swapped CNTV_CVAL_EL0 and CNTVCT_EL0.
            KvmVcpuRegister::System(aarch64_sys_reg::CNTV_CVAL_EL0) => reg_u64(
                KVM_REG_ARM64_SYSREG.into(),
                aarch64_sys_reg::CNTVCT_EL0.encoded().into(),
            ),
            KvmVcpuRegister::System(aarch64_sys_reg::CNTVCT_EL0) => reg_u64(
                KVM_REG_ARM64_SYSREG.into(),
                aarch64_sys_reg::CNTV_CVAL_EL0.encoded().into(),
            ),
            KvmVcpuRegister::System(sysreg) => {
                reg_u64(KVM_REG_ARM64_SYSREG.into(), sysreg.encoded().into())
            }
            KvmVcpuRegister::Firmware(n) => reg_u64(KVM_REG_ARM_FW.into(), n.into()),
            KvmVcpuRegister::Ccsidr(n) => demux_reg(KVM_REG_SIZE_U32, 0, n.into()),
        }
    }
}

impl VcpuAArch64 for KvmVcpu {
    fn init(&self, features: &[VcpuFeature]) -> Result<()> {
        let mut kvi = kvm_vcpu_init {
            target: KVM_ARM_TARGET_GENERIC_V8,
            features: [0; 7],
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will write exactly the size
        // of the struct.
        let ret = unsafe { ioctl_with_mut_ref(&self.vm, KVM_ARM_PREFERRED_TARGET, &mut kvi) };
        if ret != 0 {
            return errno_result();
        }

        kvi.features[0] = self.get_features_bitmap(features)?;
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_ARM_VCPU_INIT, &kvi) };
        if ret != 0 {
            return errno_result();
        }

        self.finalize(kvi.features[0])?;
        Ok(())
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
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_HAS_DEVICE_ATTR, &irq_attr) };
        if ret < 0 {
            return errno_result();
        }

        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR, &irq_attr) };
        if ret < 0 {
            return errno_result();
        }

        let init_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: KVM_ARM_VCPU_PMU_V3_INIT as u64,
            addr: 0,
            flags: 0,
        };
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR, &init_attr) };
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
        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_HAS_DEVICE_ATTR, &pvtime_attr) };
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

        // SAFETY:
        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, kvm_sys::KVM_SET_DEVICE_ATTR, &pvtime_attr) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    fn set_one_reg(&self, reg_id: VcpuRegAArch64, data: u64) -> Result<()> {
        let kvm_reg = self.kvm_reg_id(reg_id)?;
        match kvm_reg.size() {
            4 => self.set_one_kvm_reg_u32(kvm_reg, data as u32),
            8 => self.set_one_kvm_reg_u64(kvm_reg, data),
            size => panic!("bad reg size {size}"),
        }
    }

    fn get_one_reg(&self, reg_id: VcpuRegAArch64) -> Result<u64> {
        let kvm_reg = self.kvm_reg_id(reg_id)?;
        match kvm_reg.size() {
            4 => self.get_one_kvm_reg_u32(kvm_reg).map(u64::from),
            8 => self.get_one_kvm_reg_u64(kvm_reg),
            size => panic!("bad reg size {size}"),
        }
    }

    fn set_vector_reg(&self, reg_num: u8, data: u128) -> Result<()> {
        if reg_num > 31 {
            return Err(Error::new(EINVAL));
        }
        self.set_one_kvm_reg_u128(KvmVcpuRegister::V(reg_num), data)
    }

    fn get_vector_reg(&self, reg_num: u8) -> Result<u128> {
        if reg_num > 31 {
            return Err(Error::new(EINVAL));
        }
        self.get_one_kvm_reg_u128(KvmVcpuRegister::V(reg_num))
    }

    fn get_mpidr(&self) -> Result<u64> {
        self.get_one_reg(VcpuRegAArch64::System(aarch64_sys_reg::MPIDR_EL1))
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

    fn get_max_hw_bps(&self) -> Result<usize> {
        // SAFETY:
        // Safe because the kernel will only return the result of the ioctl.
        let max_hw_bps = unsafe {
            ioctl_with_val(
                &self.vm,
                KVM_CHECK_EXTENSION,
                KVM_CAP_GUEST_DEBUG_HW_BPS.into(),
            )
        };

        if max_hw_bps < 0 {
            errno_result()
        } else {
            Ok(max_hw_bps.try_into().expect("can't represent u64 as usize"))
        }
    }

    fn get_system_regs(&self) -> Result<BTreeMap<AArch64SysRegId, u64>> {
        let reg_list = self.get_reg_list()?;
        let cntvct_el0: u16 = aarch64_sys_reg::CNTVCT_EL0.encoded();
        let cntv_cval_el0: u16 = aarch64_sys_reg::CNTV_CVAL_EL0.encoded();
        let mut sys_regs = BTreeMap::new();
        for reg in reg_list {
            if (reg as u32) & KVM_REG_ARM_COPROC_MASK == KVM_REG_ARM64_SYSREG {
                let r = if reg as u16 == cntvct_el0 {
                    aarch64_sys_reg::CNTV_CVAL_EL0
                } else if reg as u16 == cntv_cval_el0 {
                    aarch64_sys_reg::CNTVCT_EL0
                } else {
                    AArch64SysRegId::from_encoded((reg & 0xFFFF) as u16)
                };
                sys_regs.insert(r, self.get_one_reg(VcpuRegAArch64::System(r))?);
                // The register representations are tricky. Double check they round trip correctly.
                assert_eq!(
                    Ok(reg),
                    self.kvm_reg_id(VcpuRegAArch64::System(r)).map(u64::from),
                );
            }
        }

        // The list of system registers below do not follow the convention of system registers
        // for bits 31-16.
        // System registers bits 31-16 == 0x0013, but not for those registers. Add them
        // explicitly
        let extra_sys_regs = [
            aarch64_sys_reg::ELR_EL1,
            aarch64_sys_reg::FPCR,
            aarch64_sys_reg::FPSR,
            aarch64_sys_reg::SP_EL1,
            aarch64_sys_reg::SPSR_EL1,
            aarch64_sys_reg::SPSR_abt,
            aarch64_sys_reg::SPSR_und,
            aarch64_sys_reg::SPSR_irq,
            aarch64_sys_reg::SPSR_fiq,
        ];
        for reg in extra_sys_regs {
            sys_regs.insert(reg, self.get_one_reg(VcpuRegAArch64::System(reg))?);
        }
        Ok(sys_regs)
    }

    fn get_cache_info(&self) -> Result<BTreeMap<u8, u64>> {
        const KVM_REG_CCSIDR: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U32 | (KVM_REG_ARM_DEMUX as u64);
        const CCSIDR_INDEX_MASK: u64 = 0xFF;
        let reg_list = self.get_reg_list()?;
        let mut cache_info = BTreeMap::new();
        for reg in reg_list {
            if (reg & !CCSIDR_INDEX_MASK) == KVM_REG_CCSIDR {
                let idx = reg as u8;
                cache_info.insert(
                    idx,
                    self.get_one_kvm_reg_u32(KvmVcpuRegister::Ccsidr(idx))?
                        .into(),
                );
            }
        }
        Ok(cache_info)
    }

    fn set_cache_info(&self, cache_info: BTreeMap<u8, u64>) -> Result<()> {
        for (idx, val) in cache_info {
            self.set_one_kvm_reg_u32(
                KvmVcpuRegister::Ccsidr(idx),
                val.try_into()
                    .expect("trying to set a u32 register with a u64 value"),
            )?;
        }
        Ok(())
    }

    fn hypervisor_specific_snapshot(&self) -> anyhow::Result<AnySnapshot> {
        let reg_list = self.get_reg_list()?;
        let mut firmware_regs = BTreeMap::new();
        for reg in reg_list {
            if (reg as u32) & KVM_REG_ARM_COPROC_MASK == KVM_REG_ARM_FW {
                firmware_regs.insert(
                    reg as u16,
                    self.get_one_kvm_reg_u64(KvmVcpuRegister::Firmware(reg as u16))?,
                );
            }
        }

        AnySnapshot::to_any(KvmSnapshot { firmware_regs })
            .context("Failed to serialize KVM specific data")
    }

    fn hypervisor_specific_restore(&self, data: AnySnapshot) -> anyhow::Result<()> {
        let deser: KvmSnapshot =
            AnySnapshot::from_any(data).context("Failed to deserialize KVM specific data")?;
        // TODO: need to set firmware registers before "create_fdt" is called, earlier in the
        // stack.
        for (id, val) in &deser.firmware_regs {
            self.set_one_kvm_reg_u64(KvmVcpuRegister::Firmware(*id), *val)?;
        }
        Ok(())
    }

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

        // SAFETY:
        // Safe because the kernel won't read past the end of the kvm_guest_debug struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_GUEST_DEBUG, &dbg) };
        if ret == 0 {
            Ok(())
        } else {
            errno_result()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KvmSnapshot {
    firmware_regs: BTreeMap<u16, u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_timer_register_mixup() {
        // Per https://docs.kernel.org/virt/kvm/api.html ARM64 system register encoding docs,
        // KVM_REG_ARM_TIMER_CVAL and KVM_REG_ARM_TIMER_CNT were accidentally defined backwards.
        // Ensure the AArch64SysRegId to KvmVcpuRegister encoding maps these to the expected
        // values.

        const KVM_REG_ARM_TIMER_CVAL: u64 = 0x6030_0000_0013_DF02;
        let cntv_cval_el0_kvm = KvmVcpuRegister::System(aarch64_sys_reg::CNTV_CVAL_EL0);
        assert_eq!(u64::from(cntv_cval_el0_kvm), KVM_REG_ARM_TIMER_CVAL);

        const KVM_REG_ARM_TIMER_CNT: u64 = 0x6030_0000_0013_DF1A;
        let cntvct_el0_kvm = KvmVcpuRegister::System(aarch64_sys_reg::CNTVCT_EL0);
        assert_eq!(u64::from(cntvct_el0_kvm), KVM_REG_ARM_TIMER_CNT);
    }
}

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

use super::{Kvm, KvmCap, KvmVcpu, KvmVm};
use crate::{
    ClockState, DeviceKind, Hypervisor, IrqSourceChip, ProtectionType, PsciVersion, VcpuAArch64,
    VcpuExit, VcpuFeature, Vm, VmAArch64, VmCap, PSCI_0_2,
};

/// Gives the ID for a register to be used with `set_one_reg`.
///
/// Pass the name of a field in `user_pt_regs` to get the corresponding register
/// ID, e.g. `arm64_core_reg!(pstate)`
///
/// To get ID for registers `x0`-`x31`, refer to the `regs` field along with the
/// register number, e.g. `arm64_core_reg!(regs, 5)` for `x5`. This is different
/// to work around `offset_of!(kvm_sys::user_pt_regs, regs[$x])` not working.
#[macro_export]
macro_rules! arm64_core_reg {
    ($reg: tt) => {{
        let off = (memoffset::offset_of!(::kvm_sys::user_pt_regs, $reg) / 4) as u64;
        ::kvm_sys::KVM_REG_ARM64
            | ::kvm_sys::KVM_REG_SIZE_U64
            | ::kvm_sys::KVM_REG_ARM_CORE as u64
            | off
    }};
    (regs, $x: literal) => {{
        let off = ((memoffset::offset_of!(::kvm_sys::user_pt_regs, regs)
            + ($x * ::std::mem::size_of::<u64>()))
            / 4) as u64;
        ::kvm_sys::KVM_REG_ARM64
            | ::kvm_sys::KVM_REG_SIZE_U64
            | ::kvm_sys::KVM_REG_ARM_CORE as u64
            | off
    }};
}

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
        if event_flags & u64::from(KVM_SYSTEM_EVENT_RESET_FLAG_PSCI_RESET2) != 0 {
            // Read reset_type and cookie from x1 and x2.
            let reset_type = self.get_one_reg(arm64_core_reg!(regs, 1))?;
            let cookie = self.get_one_reg(arm64_core_reg!(regs, 2))?;
            warn!(
                "PSCI SYSTEM_RESET2 with reset_type={:#x}, cookie={:#x}",
                reset_type, cookie
            );
        }
        Ok(VcpuExit::SystemEventReset)
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

    fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()> {
        let data_ref = &data as *const u64;
        let onereg = kvm_one_reg {
            id: reg_id,
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

    fn get_one_reg(&self, reg_id: u64) -> Result<u64> {
        let val: u64 = 0;
        let mut onereg = kvm_one_reg {
            id: reg_id,
            addr: (&val as *const u64) as u64,
        };

        // Safe because we allocated the struct and we know the kernel will read exactly the size of
        // the struct.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_ONE_REG(), &mut onereg) };
        if ret == 0 {
            Ok(val)
        } else {
            return errno_result();
        }
    }

    fn get_psci_version(&self) -> Result<PsciVersion> {
        // The definition of KVM_REG_ARM_PSCI_VERSION is in arch/arm64/include/uapi/asm/kvm.h.
        const KVM_REG_ARM_PSCI_VERSION: u64 =
            KVM_REG_ARM64 | (KVM_REG_SIZE_U64 as u64) | (KVM_REG_ARM_FW as u64);

        let version = if let Ok(v) = self.get_one_reg(KVM_REG_ARM_PSCI_VERSION) {
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

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{EINVAL, ENOMEM, ENOSYS, ENXIO};

use base::{
    errno_result, error, ioctl_with_mut_ref, ioctl_with_ref, Error, MemoryMappingBuilder, Result,
};
use kvm_sys::*;
use vm_memory::GuestAddress;

use super::{KvmCap, KvmVcpu, KvmVm};
use crate::{
    ClockState, DeviceKind, Hypervisor, IrqSourceChip, PsciVersion, VcpuAArch64, VcpuFeature, Vm,
    VmAArch64, VmCap,
};

impl KvmVm {
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

    fn enable_protected_vm(&mut self, fw_addr: GuestAddress, fw_max_size: u64) -> Result<()> {
        if !self.check_capability(VmCap::Protected) {
            return Err(Error::new(ENOSYS));
        }
        let info = self.get_protected_vm_info()?;
        let memslot = if info.firmware_size == 0 {
            u64::MAX
        } else {
            if info.firmware_size > fw_max_size {
                return Err(Error::new(ENOMEM));
            }
            let mem = MemoryMappingBuilder::new(info.firmware_size as usize)
                .build()
                .map_err(|_| Error::new(EINVAL))?;
            self.add_memory_region(fw_addr, Box::new(mem), false, false)? as u64
        };
        // Safe because none of the args are pointers.
        unsafe {
            self.enable_raw_capability(
                KvmCap::ArmProtectedVm,
                KVM_CAP_ARM_PROTECTED_VM_FLAGS_ENABLE,
                &[memslot, 0, 0, 0],
            )
        }
    }

    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuAArch64>> {
        // create_vcpu is declared separately in VmAArch64 and VmX86, so it can return VcpuAArch64
        // or VcpuX86.  But both use the same implementation in KvmVm::create_vcpu.
        Ok(Box::new(KvmVm::create_vcpu(self, id)?))
    }
}

impl KvmVcpu {
    /// Arch-specific implementation of `Vcpu::pvclock_ctrl`.  Always returns an error on AArch64.
    pub fn pvclock_ctrl_arch(&self) -> Result<()> {
        Err(Error::new(ENXIO))
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

        match self.get_one_reg(KVM_REG_ARM_PSCI_VERSION) {
            Ok(v) => {
                let major = (v >> PSCI_VERSION_MAJOR_SHIFT) as u32;
                let minor = (v as u32) & PSCI_VERSION_MINOR_MASK;
                Ok(PsciVersion { major, minor })
            }
            Err(_) => {
                // When `KVM_REG_ARM_PSCI_VERSION` is not supported, we can return PSCI 0.2, as vCPU
                // has been initialized with `KVM_ARM_VCPU_PSCI_0_2` successfully.
                Ok(PsciVersion { major: 0, minor: 2 })
            }
        }
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

#[cfg(test)]
mod tests {
    use super::super::Kvm;
    use super::*;
    use crate::{IrqRoute, IrqSource, IrqSourceChip};
    use vm_memory::{GuestAddress, GuestMemory};

    #[test]
    fn set_gsi_routing() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vm = KvmVm::new(&kvm, gm).unwrap();
        vm.create_irq_chip().unwrap();
        vm.set_gsi_routing(&[]).unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Gic,
                pin: 3,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[IrqRoute {
            gsi: 1,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        }])
        .unwrap();
        vm.set_gsi_routing(&[
            IrqRoute {
                gsi: 1,
                source: IrqSource::Irqchip {
                    chip: IrqSourceChip::Gic,
                    pin: 3,
                },
            },
            IrqRoute {
                gsi: 2,
                source: IrqSource::Msi {
                    address: 0xf000000,
                    data: 0xa0,
                },
            },
        ])
        .unwrap();
    }
}

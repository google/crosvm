// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::errno_result;
use base::ioctl_with_ref;
use base::AsRawDescriptor;
use base::Error as BaseError;
use base::RawDescriptor;
use base::Result;
use base::SafeDescriptor;
use hypervisor::kvm::KvmVcpu;
use hypervisor::kvm::KvmVm;
use hypervisor::DeviceKind;
use hypervisor::IrqRoute;
use hypervisor::Vm;
use kvm_sys::*;
use sync::Mutex;

use crate::IrqChip;
use crate::IrqChipRiscv64;

const RISCV_IRQCHIP: u64 = 0x0800_0000;

const KVM_DEV_RISCV_AIA_ADDR_APLIC: u64 = 0;

pub const AIA_IMSIC_BASE: u64 = RISCV_IRQCHIP;
const KVM_DEV_RISCV_IMSIC_SIZE: u64 = 0x1000;

pub const fn aia_addr_imsic(vcpu_id: u64) -> u64 {
    1 + vcpu_id
}

pub const fn aia_imsic_addr(hart: usize) -> u64 {
    AIA_IMSIC_BASE + (hart as u64) * KVM_DEV_RISCV_IMSIC_SIZE
}

pub const fn aia_imsic_size(num_harts: usize) -> u64 {
    num_harts as u64 * KVM_DEV_RISCV_IMSIC_SIZE
}

pub const fn aia_aplic_addr(num_harts: usize) -> u64 {
    AIA_IMSIC_BASE + (num_harts as u64) * KVM_DEV_RISCV_IMSIC_SIZE
}
pub const AIA_APLIC_SIZE: u32 = 0x4000;

// Connstants for get/set attributes calls.
const KVM_DEV_RISCV_AIA_GRP_CONFIG: u32 = 0;

const KVM_DEV_RISCV_AIA_CONFIG_MODE: u64 = 0;
const KVM_DEV_RISCV_AIA_CONFIG_IDS: u64 = 1;
const KVM_DEV_RISCV_AIA_CONFIG_SRCS: u64 = 2;
const KVM_DEV_RISCV_AIA_CONFIG_HART_BITS: u64 = 5;

pub const IMSIC_MAX_INT_IDS: u64 = 2047;

// CONFIG_MODE values
const AIA_MODE_HWACCEL: u32 = 1;
const AIA_MODE_AUTO: u32 = 2;

const KVM_DEV_RISCV_AIA_GRP_ADDR: u32 = 1;

const KVM_DEV_RISCV_AIA_GRP_CTRL: u32 = 2;

struct AiaDescriptor(SafeDescriptor);

impl AiaDescriptor {
    fn try_clone(&self) -> Result<AiaDescriptor> {
        self.0.try_clone().map(AiaDescriptor)
    }

    fn aia_init(&self) -> Result<()> {
        let init_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CTRL,
            attr: KVM_DEV_RISCV_AIA_CTRL_INIT as u64,
            addr: 0,
            flags: 0,
        };

        // Safe because we allocated the struct that's being passed in, and raw_aia_mode is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), &init_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    fn get_num_ids(&self) -> Result<u32> {
        let mut aia_num_ids = 0;
        let raw_num_ids = &mut aia_num_ids as *mut u32;

        let aia_num_ids_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_IDS,
            addr: raw_num_ids as u64,
            flags: 0,
        };

        // Safe because we allocated the struct that's being passed in, and raw_num_ids is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DEVICE_ATTR(), &aia_num_ids_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(aia_num_ids)
    }

    fn get_aia_mode(&self) -> Result<u32> {
        let mut aia_mode: u32 = AIA_MODE_HWACCEL;
        let raw_aia_mode = &mut aia_mode as *mut u32;
        let aia_mode_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_MODE,
            addr: raw_aia_mode as u64,
            flags: 0,
        };
        // Safe because we allocated the struct that's being passed in, and raw_aia_mode is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DEVICE_ATTR(), &aia_mode_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(aia_mode)
    }

    fn set_num_sources(&self, num_sources: u32) -> Result<()> {
        let raw_num_sources = &num_sources as *const u32;
        let kvm_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_SRCS,
            addr: raw_num_sources as u64,
            flags: 0,
        };
        // Safe because we allocated the struct that's being passed in, and raw_aia_mode is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), &kvm_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    fn set_hart_bits(&self, hart_bits: u32) -> Result<()> {
        let raw_hart_bits = &hart_bits as *const u32;
        let kvm_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_HART_BITS,
            addr: raw_hart_bits as u64,
            flags: 0,
        };
        // Safe because we allocated the struct that's being passed in, and raw_aia_mode is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), &kvm_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }

    fn set_aplic_addrs(&self, num_vcpus: usize) -> Result<()> {
        /* Set AIA device addresses */
        let aplic_addr = aia_aplic_addr(num_vcpus);
        let raw_aplic_addr = &aplic_addr as *const u64;
        let kvm_attr = kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_ADDR,
            attr: KVM_DEV_RISCV_AIA_ADDR_APLIC,
            addr: raw_aplic_addr as u64,
            flags: 0,
        };
        // Safe because we allocated the struct that's being passed in, and raw_aplic_addr is pointing
        // to a uniquely owned local, mutable variable.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), &kvm_attr) };
        if ret != 0 {
            return errno_result();
        }
        for i in 0..num_vcpus {
            let imsic_addr = aia_imsic_addr(i);
            let raw_imsic_addr = &imsic_addr as *const u64;
            let kvm_attr = kvm_device_attr {
                group: KVM_DEV_RISCV_AIA_GRP_ADDR,
                attr: aia_addr_imsic(i as u64),
                addr: raw_imsic_addr as u64,
                flags: 0,
            };
            // Safe because we allocated the struct that's being passed in, and raw_imsic_addr is
            // pointing to a uniquely owned local, mutable variable.
            let ret = unsafe { ioctl_with_ref(self, KVM_SET_DEVICE_ATTR(), &kvm_attr) };
            if ret != 0 {
                return errno_result();
            }
        }
        Ok(())
    }
}

impl AsRawDescriptor for AiaDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

/// IrqChip implementation where the entire IrqChip is emulated by KVM.
///
/// This implementation will use the KVM API to create and configure the in-kernel irqchip.
pub struct KvmKernelIrqChip {
    pub(super) vm: KvmVm,
    pub(super) vcpus: Arc<Mutex<Vec<Option<KvmVcpu>>>>,
    num_vcpus: usize,
    num_ids: usize,     // number of imsics ids
    num_sources: usize, // number of aplic sources
    aia: AiaDescriptor,
    device_kind: DeviceKind,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

impl KvmKernelIrqChip {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm, num_vcpus: usize) -> Result<KvmKernelIrqChip> {
        let aia = AiaDescriptor(vm.create_device(DeviceKind::RiscvAia)?);

        let aia_mode = aia.get_aia_mode()?;
        // Only support full emulation in the kernel.
        if aia_mode != AIA_MODE_HWACCEL && aia_mode != AIA_MODE_AUTO {
            return Err(BaseError::new(libc::ENOTSUP));
        }

        // Don't need any wired interrupts, riscv can run PCI/MSI(X) only.
        const NUM_SOURCES: u32 = 0;
        aia.set_num_sources(NUM_SOURCES)?;

        let num_ids = aia.get_num_ids()?;

        // set the number of bits needed for this count of harts.
        // Need at least one bit.
        let max_hart_idx = num_vcpus as u64 - 1;
        let num_hart_bits = std::cmp::max(1, 64 - max_hart_idx.leading_zeros());
        aia.set_hart_bits(num_hart_bits)?;

        Ok(KvmKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            num_vcpus,
            num_ids: num_ids as usize,
            num_sources: NUM_SOURCES as usize,
            aia,
            device_kind: DeviceKind::RiscvAia,
            routes: Arc::new(Mutex::new(kvm_default_irq_routing_table(
                NUM_SOURCES as usize,
            ))),
        })
    }

    /// Attempt to create a shallow clone of this riscv64 KvmKernelIrqChip instance.
    /// This is the arch-specific impl used by `KvmKernelIrqChip::clone()`.
    pub(super) fn arch_try_clone(&self) -> Result<Self> {
        Ok(KvmKernelIrqChip {
            vm: self.vm.try_clone()?,
            vcpus: self.vcpus.clone(),
            num_vcpus: self.num_vcpus,
            num_ids: self.num_ids,
            num_sources: self.num_sources,
            aia: self.aia.try_clone()?,
            device_kind: self.device_kind,
            routes: self.routes.clone(),
        })
    }
}

impl IrqChipRiscv64 for KvmKernelIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipRiscv64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    fn finalize(&self) -> Result<()> {
        // The kernel needs the number of vcpus finalized before setting up the address for each
        // interrupt controller.
        self.aia.set_aplic_addrs(self.num_vcpus)?;
        self.aia.aia_init()?;
        Ok(())
    }

    fn get_num_ids_sources(&self) -> (usize, usize) {
        (self.num_ids, self.num_sources)
    }
}

/// Default RiscV routing table.
fn kvm_default_irq_routing_table(num_sources: usize) -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..num_sources {
        routes.push(IrqRoute::aia_irq_route(i as u32));
    }

    routes
}

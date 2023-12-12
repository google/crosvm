// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::errno_result;
use base::ioctl_with_ref;
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
use crate::IrqChipAArch64;

/// Default ARM routing table.  AARCH64_GIC_NR_SPIS pins go to VGIC.
fn kvm_default_irq_routing_table() -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..AARCH64_GIC_NR_SPIS {
        routes.push(IrqRoute::gic_irq_route(i));
    }

    routes
}

/// IrqChip implementation where the entire IrqChip is emulated by KVM.
///
/// This implementation will use the KVM API to create and configure the in-kernel irqchip.
pub struct KvmKernelIrqChip {
    pub(super) vm: KvmVm,
    pub(super) vcpus: Arc<Mutex<Vec<Option<KvmVcpu>>>>,
    vgic: SafeDescriptor,
    device_kind: DeviceKind,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;

// This is the minimum number of SPI interrupts aligned to 32 + 32 for the
// PPI (16) and GSI (16).
pub const AARCH64_GIC_NR_IRQS: u32 = 64;
// Number of SPIs (32), which is the NR_IRQS (64) minus the number of PPIs (16) and GSIs (16)
pub const AARCH64_GIC_NR_SPIS: u32 = 32;

const AARCH64_AXI_BASE: u64 = 0x40000000;

impl KvmKernelIrqChip {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm, num_vcpus: usize) -> Result<KvmKernelIrqChip> {
        let cpu_if_addr: u64 = AARCH64_GIC_CPUI_BASE;
        let dist_if_addr: u64 = AARCH64_GIC_DIST_BASE;
        let redist_addr: u64 = dist_if_addr - (AARCH64_GIC_REDIST_SIZE * num_vcpus as u64);
        let raw_cpu_if_addr = &cpu_if_addr as *const u64;
        let raw_dist_if_addr = &dist_if_addr as *const u64;
        let raw_redist_addr = &redist_addr as *const u64;

        let cpu_if_attr = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: KVM_VGIC_V2_ADDR_TYPE_CPU as u64,
            addr: raw_cpu_if_addr as u64,
            flags: 0,
        };
        let redist_attr = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: KVM_VGIC_V3_ADDR_TYPE_REDIST as u64,
            addr: raw_redist_addr as u64,
            flags: 0,
        };
        let mut dist_attr = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            addr: raw_dist_if_addr as u64,
            attr: 0,
            flags: 0,
        };

        let (vgic, device_kind, cpu_redist_attr, dist_attr_attr) =
            match vm.create_device(DeviceKind::ArmVgicV3) {
                Err(_) => (
                    vm.create_device(DeviceKind::ArmVgicV2)?,
                    DeviceKind::ArmVgicV2,
                    cpu_if_attr,
                    KVM_VGIC_V2_ADDR_TYPE_DIST as u64,
                ),
                Ok(vgic) => (
                    vgic,
                    DeviceKind::ArmVgicV3,
                    redist_attr,
                    KVM_VGIC_V3_ADDR_TYPE_DIST as u64,
                ),
            };
        dist_attr.attr = dist_attr_attr;

        // SAFETY:
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR(), &cpu_redist_attr) };
        if ret != 0 {
            return errno_result();
        }

        // SAFETY:
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR(), &dist_attr) };
        if ret != 0 {
            return errno_result();
        }

        // We need to tell the kernel how many irqs to support with this vgic
        let nr_irqs: u32 = AARCH64_GIC_NR_IRQS;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let nr_irqs_attr = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        // SAFETY:
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR(), &nr_irqs_attr) };
        if ret != 0 {
            return errno_result();
        }

        Ok(KvmKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            vgic,
            device_kind,
            routes: Arc::new(Mutex::new(kvm_default_irq_routing_table())),
        })
    }

    /// Attempt to create a shallow clone of this aarch64 KvmKernelIrqChip instance.
    pub(super) fn arch_try_clone(&self) -> Result<Self> {
        Ok(KvmKernelIrqChip {
            vm: self.vm.try_clone()?,
            vcpus: self.vcpus.clone(),
            vgic: self.vgic.try_clone()?,
            device_kind: self.device_kind,
            routes: self.routes.clone(),
        })
    }
}

impl IrqChipAArch64 for KvmKernelIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipAArch64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    fn get_vgic_version(&self) -> DeviceKind {
        self.device_kind
    }

    fn finalize(&self) -> Result<()> {
        let init_gic_attr = kvm_device_attr {
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: KVM_DEV_ARM_VGIC_CTRL_INIT as u64,
            addr: 0,
            flags: 0,
        };

        // SAFETY:
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe { ioctl_with_ref(&self.vgic, KVM_SET_DEVICE_ATTR(), &init_gic_attr) };
        if ret != 0 {
            return errno_result();
        }
        Ok(())
    }
}

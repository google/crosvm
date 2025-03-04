// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;

use aarch64_sys_reg::ICC_CTLR_EL1;
use anyhow::anyhow;
use anyhow::Context;
use base::errno_result;
use base::ioctl_with_ref;
use base::Result;
use base::SafeDescriptor;
use hypervisor::kvm::KvmVcpu;
use hypervisor::kvm::KvmVm;
use hypervisor::DeviceKind;
use hypervisor::IrqRoute;
use hypervisor::MPState;
use hypervisor::VcpuAArch64;
use hypervisor::Vm;
use kvm_sys::*;
use serde::Deserialize;
use serde::Serialize;
use snapshot::AnySnapshot;
use sync::Mutex;

use crate::icc_regs;
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
    vgic_its: Option<SafeDescriptor>,
    device_kind: DeviceKind,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64 = 0x40000000 - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;
const AARCH64_GIC_ITS_BASE: u64 = 0x40000000;

// This is the minimum number of SPI interrupts aligned to 32 + 32 for the
// PPI (16) and GSI (16).
pub const AARCH64_GIC_NR_IRQS: u32 = 64;
// Number of SPIs (32), which is the NR_IRQS (64) minus the number of PPIs (16) and GSIs (16)
pub const AARCH64_GIC_NR_SPIS: u32 = 32;

impl KvmKernelIrqChip {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm, num_vcpus: usize, allow_vgic_its: bool) -> Result<KvmKernelIrqChip> {
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
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR, &cpu_redist_attr) };
        if ret != 0 {
            return errno_result();
        }

        // SAFETY:
        // Safe because we allocated the struct that's being passed in
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR, &dist_attr) };
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
        let ret = unsafe { ioctl_with_ref(&vgic, KVM_SET_DEVICE_ATTR, &nr_irqs_attr) };
        if ret != 0 {
            return errno_result();
        }

        // Create an ITS if allowed and supported.
        let vgic_its = 'its: {
            if !allow_vgic_its || device_kind != DeviceKind::ArmVgicV3 {
                break 'its None;
            }
            let vgic_its = match vm.create_device(DeviceKind::ArmVgicIts) {
                Ok(x) => x,
                Err(e) if e.errno() == libc::ENODEV => break 'its None, // unsupported
                Err(e) => return Err(e),
            };
            // Set ITS base address.
            let its_addr = AARCH64_GIC_ITS_BASE;
            let its_addr_attr = kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_ADDR,
                attr: KVM_VGIC_ITS_ADDR_TYPE.into(),
                addr: &its_addr as *const u64 as u64,
                flags: 0,
            };
            // SAFETY: Safe because we allocated the struct that's being passed in.
            let ret = unsafe { ioctl_with_ref(&vgic_its, KVM_SET_DEVICE_ATTR, &its_addr_attr) };
            if ret != 0 {
                return errno_result();
            }
            Some(vgic_its)
        };

        Ok(KvmKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            vgic,
            vgic_its,
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
            vgic_its: self
                .vgic_its
                .as_ref()
                .map(|fd| fd.try_clone())
                .transpose()?,
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

    fn has_vgic_its(&self) -> bool {
        self.vgic_its.is_some()
    }

    fn snapshot(&self, _cpus_num: usize) -> anyhow::Result<AnySnapshot> {
        if self.vgic_its.is_some() {
            return Err(anyhow!("snapshot of vGIC ITS not supported yet"));
        }
        if self.device_kind == DeviceKind::ArmVgicV3 {
            let save_gic_attr = kvm_device_attr {
                group: KVM_DEV_ARM_VGIC_GRP_CTRL,
                attr: KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES as u64,
                addr: 0,
                flags: 0,
            };
            // SAFETY:
            // Safe because we allocated the struct that's being passed in
            // Safe because the device interrupts get stored in guest memory
            let ret = unsafe { ioctl_with_ref(&self.vgic, KVM_SET_DEVICE_ATTR, &save_gic_attr) };
            if ret != 0 {
                return errno_result()
                    .context("ioctl KVM_SET_DEVICE_ATTR for save_gic_attr failed.")?;
            }
            let mut cpu_specific: BTreeMap<u64, CpuSpecificState> = BTreeMap::new();
            let vcpus = self.vcpus.lock();
            for vcpu in vcpus.iter().flatten() {
                let mut cpu_sys_regs: BTreeMap<u16, u64> = BTreeMap::new();
                let mut redist_regs: Vec<u32> = Vec::new();
                let mpidr = mpidr_concat_aff(vcpu.get_mpidr()?);
                // SAFETY:
                // Safe because we are specifying CPU SYSREGS, which is 64 bits.
                // https://docs.kernel.org/virt/kvm/devices/arm-vgic-v3.html
                let ctlr = unsafe {
                    get_kvm_device_attr_u64(
                        &self.vgic,
                        KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                        mpidr | ICC_CTLR_EL1.encoded() as u64,
                    )?
                };
                // The reported number of priority bits is missing 1, as per ARM documentation.
                // See register ICC_CTLR_EL1 for more information. Add the missing 1.
                let prio_bits = (((ctlr & 0x700) >> 8) + 1) as u8;
                cpu_sys_regs.insert(ICC_CTLR_EL1.encoded(), ctlr);
                get_cpu_vgic_regs(&self.vgic, &mut cpu_sys_regs, mpidr, prio_bits)?;
                redist_regs.append(&mut get_redist_regs(&self.vgic, mpidr)?);
                cpu_specific.insert(
                    mpidr,
                    CpuSpecificState {
                        cpu_sys_regs,
                        redist_regs,
                        mp_state: MPState::from(&vcpu.get_mp_state()?),
                    },
                );
            }
            AnySnapshot::to_any(VgicSnapshot {
                cpu_specific,
                dist_regs: get_dist_regs(&self.vgic)?,
            })
        } else {
            Err(anyhow!("Unsupported VGIC version for snapshot"))
        }
    }

    fn restore(&mut self, data: AnySnapshot, _vcpus_num: usize) -> anyhow::Result<()> {
        if self.device_kind == DeviceKind::ArmVgicV3 {
            // SAVE_PENDING_TABLES operation wrote the pending tables into guest memory.
            let deser: VgicSnapshot =
                AnySnapshot::from_any(data).context("Failed to deserialize vgic data")?;
            let vcpus = self.vcpus.lock();
            for vcpu in vcpus.iter().flatten() {
                let mpidr = mpidr_concat_aff(vcpu.get_mpidr()?);
                let mpidr_data = deser
                    .cpu_specific
                    .get(&mpidr)
                    .with_context(|| format!("CPU with MPIDR {} does not exist", mpidr))?;
                set_cpu_vgic_regs(&self.vgic, mpidr, &mpidr_data.cpu_sys_regs)?;
                set_redist_regs(&self.vgic, mpidr, &mpidr_data.redist_regs)?;
                vcpu.set_mp_state(&kvm_mp_state::from(&mpidr_data.mp_state))?;
            }
            set_dist_regs(&self.vgic, &deser.dist_regs)?;
            Ok(())
        } else {
            Err(anyhow!("Unsupported VGIC version for restore"))
        }
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
        let ret = unsafe { ioctl_with_ref(&self.vgic, KVM_SET_DEVICE_ATTR, &init_gic_attr) };
        if ret != 0 {
            return errno_result();
        }
        if let Some(vgic_its) = &self.vgic_its {
            // SAFETY:
            // Safe because we allocated the struct that's being passed in
            let ret = unsafe { ioctl_with_ref(vgic_its, KVM_SET_DEVICE_ATTR, &init_gic_attr) };
            if ret != 0 {
                return errno_result();
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct VgicSnapshot {
    cpu_specific: BTreeMap<u64, CpuSpecificState>,
    dist_regs: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
struct CpuSpecificState {
    // Key: Register ID.
    cpu_sys_regs: BTreeMap<u16, u64>,
    redist_regs: Vec<u32>,
    mp_state: MPState,
}

// # Safety
// Unsafe if incorrect group or attr (offset) provided.
// The caller must ensure the group is 32 bits and attr is for a 32 bit value
unsafe fn get_kvm_device_attr_u32(
    vgic: &SafeDescriptor,
    group: u32,
    attr: u64,
) -> anyhow::Result<u32> {
    let mut val: u32 = 0;
    let device_attr = kvm_device_attr {
        group,
        attr,
        addr: (&mut val as *mut u32) as u64,
        flags: 0,
    };
    // SAFETY:
    // Unsafe if wrong group is provided, which could lead to trying to read from a 64 bit register
    // to a 32 bit register.
    // Unsafe if wrong attr (offset) is provided
    let ret = unsafe { ioctl_with_ref(vgic, KVM_GET_DEVICE_ATTR, &device_attr) };
    if ret != 0 {
        errno_result().with_context(|| {
            format!(
                "ioctl KVM_GET_DEVICE_ATTR_u32 for attr:{} failed.",
                device_attr.attr
            )
        })
    } else {
        Ok(val)
    }
}

// # Safety
// Unsafe if incorrect group or attr (offset) provided.
// The caller must ensure the group is 32 bits and attr is for a 64 bit value
unsafe fn get_kvm_device_attr_u64(
    vgic: &SafeDescriptor,
    group: u32,
    attr: u64,
) -> anyhow::Result<u64> {
    let mut val: u64 = 0;
    let device_attr = kvm_device_attr {
        group,
        attr,
        addr: (&mut val as *mut u64) as u64,
        flags: 0,
    };
    // SAFETY:
    // Unsafe  if wrong group is passed, which could lead to trying to read from a 32 bit register
    // to a 64 bit register. The read will succeed but the attr (offset) would need to be correct,
    // otherwise data could be skipped.
    // Unsafe if wrong attr (offset) is provided
    let ret = unsafe { ioctl_with_ref(vgic, KVM_GET_DEVICE_ATTR, &device_attr) };
    if ret != 0 {
        errno_result().with_context(|| {
            format!(
                "ioctl KVM_GET_DEVICE_ATTR_u64 for attr:{} failed.",
                device_attr.attr
            )
        })
    } else {
        Ok(val)
    }
}

// # Safety
// Unsafe if incorrect group or attr (offset) provided.
// The caller must ensure the group is 32 bits and attr is for a 32 bit value
unsafe fn set_kvm_device_attr_u32(
    vgic: &SafeDescriptor,
    group: u32,
    attr: u64,
    val: &u32,
) -> anyhow::Result<()> {
    let device_attr = kvm_device_attr {
        group,
        attr,
        addr: (val as *const u32) as u64,
        flags: 0,
    };
    // SAFETY:
    // Unsafe if the group provided is incorrect, 64 bits may be written to a 32 bit range
    // Unsafe if the wrong offset is provided
    let ret = unsafe { ioctl_with_ref(vgic, KVM_SET_DEVICE_ATTR, &device_attr) };
    if ret != 0 {
        errno_result().with_context(|| {
            format!(
                "ioctl KVM_SET_DEVICE_ATTR_u32 for attr:{} failed.",
                device_attr.attr
            )
        })
    } else {
        Ok(())
    }
}

// # Safety
// Unsafe if incorrect group or attr (offset) provided.
// The caller must ensure the group is 32 bits and attr is for a 64 bit value
unsafe fn set_kvm_device_attr_u64(
    vgic: &SafeDescriptor,
    group: u32,
    attr: u64,
    val: &u64,
) -> anyhow::Result<()> {
    let device_attr = kvm_device_attr {
        group,
        attr,
        addr: (val as *const u64) as u64,
        flags: 0,
    };
    // SAFETY:
    // Unsafe if the wrong group, 32 bits may be written to a 64 bit range,
    // potentially overwriting other the higher 32 bits of a 64 bit register
    // Unsafe if the wrong offset is provided
    let ret = unsafe { ioctl_with_ref(vgic, KVM_SET_DEVICE_ATTR, &device_attr) };
    if ret != 0 {
        errno_result().with_context(|| {
            format!(
                "ioctl KVM_SET_DEVICE_ATTR_u64 for attr:{} failed.",
                device_attr.attr
            )
        })
    } else {
        Ok(())
    }
}

fn get_cpu_vgic_regs(
    vgic: &SafeDescriptor,
    vgic_data: &mut BTreeMap<u16, u64>,
    mpidr: u64,
    prio_bits: u8,
) -> anyhow::Result<()> {
    for reg in icc_regs(prio_bits)? {
        let offset = reg.encoded();
        // SAFETY:
        // Safe because we are specifying CPU SYSREGS, which is 64 bits.
        let val = unsafe {
            get_kvm_device_attr_u64(
                vgic,
                KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                mpidr | offset as u64,
            )?
        };
        vgic_data.insert(offset, val);
    }
    Ok(())
}

fn get_redist_regs(vgic: &SafeDescriptor, mpidr: u64) -> anyhow::Result<Vec<u32>> {
    let mut vgic_data: Vec<u32> = Vec::new();
    for offset in (0..AARCH64_GIC_REDIST_SIZE).step_by(4) {
        // SAFETY:
        // Safe because we are specifying REDIST REGS, which is 32 bits.
        let val = unsafe {
            get_kvm_device_attr_u32(vgic, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, mpidr | offset)?
        };
        vgic_data.push(val);
    }
    Ok(vgic_data)
}

fn get_dist_regs(vgic: &SafeDescriptor) -> anyhow::Result<Vec<u32>> {
    let mut vgic_data: Vec<u32> = Vec::new();
    for offset in (0..AARCH64_GIC_DIST_SIZE).step_by(4) {
        // SAFETY:
        // Safe because we are specifying DIST REGS, which is 32 bits.
        let val = unsafe { get_kvm_device_attr_u32(vgic, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, offset)? };
        vgic_data.push(val);
    }
    Ok(vgic_data)
}

fn set_cpu_vgic_regs(
    vgic: &SafeDescriptor,
    mpidr: u64,
    data: &BTreeMap<u16, u64>,
) -> anyhow::Result<()> {
    for (offset, val) in data.iter() {
        // SAFETY:
        // Safe because we are specifying CPU SYSREGS, which is 64 bits.
        unsafe {
            set_kvm_device_attr_u64(
                vgic,
                KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
                mpidr | *offset as u64,
                val,
            )?
        };
    }
    Ok(())
}

fn set_redist_regs(vgic: &SafeDescriptor, mpidr: u64, data: &[u32]) -> anyhow::Result<()> {
    let mut offset = 0;
    for val in data.iter() {
        // SAFETY:
        // Safe because we are specifying REDIST REGS, which is 32 bits.
        unsafe {
            set_kvm_device_attr_u32(vgic, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, mpidr | offset, val)?
        };
        // Step by 4 for offset
        offset += 4;
    }
    Ok(())
}

fn set_dist_regs(vgic: &SafeDescriptor, data: &[u32]) -> anyhow::Result<()> {
    let mut offset = 0;
    for val in data.iter() {
        // SAFETY:
        // Safe because we are specifying DIST REGS, which is 32 bits.
        unsafe { set_kvm_device_attr_u32(vgic, KVM_DEV_ARM_VGIC_GRP_DIST_REGS, offset, val)? };
        // Step by 4 for offset
        offset += 4;
    }
    Ok(())
}

fn mpidr_concat_aff(mpidr: u64) -> u64 {
    // https://docs.kernel.org/virt/kvm/devices/arm-vgic-v3.html
    // MPIDR described as Aff3 | Aff2 | Aff1 | Aff0. (32 bits).
    // The structure of the returned value of MPIDR in Arm is a bit different:
    // https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/MPIDR-EL1--Multiprocessor-Affinity-Register
    // RES0 | Aff3 | RES1 | U | RES0 | MT | Aff2 | Aff1 | Aff0
    // 63-40| 39-32|  31  | 30|  29  | 24 | 23-16| 15-8 | 7-0
    let mpidr_aff_concat: u32 = ((mpidr & 0xFF << 32) >> 8) as u32 | mpidr as u32 & 0x00FFFFFF;
    ((mpidr_aff_concat as u64) << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT)
        & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64
}

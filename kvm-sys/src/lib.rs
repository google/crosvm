// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Somehow this one gets missed by bindgen
pub const KVM_EXIT_IO_OUT: ::std::os::raw::c_uint = 1;

// Each ioctl number gets a function instead of a constant because size_of can
// not be used in const expressions.
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => (
        pub fn $name() -> ::std::os::raw::c_ulong {
            (($dir << _IOC_DIRSHIFT) |
            ($ty << _IOC_TYPESHIFT) |
            ($nr<< _IOC_NRSHIFT) |
            ($size << _IOC_SIZESHIFT)) as ::std::os::raw::c_ulong
        }
    )
}

macro_rules! ioctl_io_nr {
    ($name:ident, $nr:expr) => (
        ioctl_ioc_nr!($name, _IOC_NONE, KVMIO, $nr, 0);
    )
}

macro_rules! ioctl_ior_nr {
    ($name:ident, $nr:expr, $size:ty) => (
        ioctl_ioc_nr!($name, _IOC_READ, KVMIO, $nr, ::std::mem::size_of::<$size>() as u32);
    )
}

macro_rules! ioctl_iow_nr {
    ($name:ident, $nr:expr, $size:ty) => (
        ioctl_ioc_nr!($name, _IOC_WRITE, KVMIO, $nr, ::std::mem::size_of::<$size>() as u32);
    )
}

macro_rules! ioctl_iowr_nr {
    ($name:ident, $nr:expr, $size:ty) => (
        ioctl_ioc_nr!($name, _IOC_READ|_IOC_WRITE, KVMIO, $nr, ::std::mem::size_of::<$size>() as u32);
    )
}

// Each of the below modules defines ioctls specific to their platform.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    // generated with bindgen /usr/include/linux/kvm.h --no-unstable-rust --constified-enum '*'
    pub mod bindings;
    pub use bindings::*;

    ioctl_iowr_nr!(KVM_GET_MSR_INDEX_LIST, 0x02, kvm_msr_list);
    ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, 0x05, kvm_cpuid2);
    ioctl_iowr_nr!(KVM_GET_EMULATED_CPUID, 0x09, kvm_cpuid2);
    ioctl_iow_nr!(KVM_SET_MEMORY_ALIAS, 0x43, kvm_memory_alias);
    ioctl_iow_nr!(KVM_XEN_HVM_CONFIG, 0x7a, kvm_xen_hvm_config);
    ioctl_ior_nr!(KVM_GET_PIT2, 0x9f, kvm_pit_state2);
    ioctl_iow_nr!(KVM_SET_PIT2, 0xa0, kvm_pit_state2);
    ioctl_iowr_nr!(KVM_GET_MSRS, 0x88, kvm_msrs);
    ioctl_iow_nr!(KVM_SET_MSRS, 0x89, kvm_msrs);
    ioctl_iow_nr!(KVM_SET_CPUID, 0x8a, kvm_cpuid);
    ioctl_ior_nr!(KVM_GET_LAPIC, 0x8e, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_LAPIC, 0x8f, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_CPUID2, 0x90, kvm_cpuid2);
    ioctl_iowr_nr!(KVM_GET_CPUID2, 0x91, kvm_cpuid2);
    ioctl_iow_nr!(KVM_X86_SETUP_MCE, 0x9c, __u64);
    ioctl_ior_nr!(KVM_X86_GET_MCE_CAP_SUPPORTED, 0x9d, __u64);
    ioctl_iow_nr!(KVM_X86_SET_MCE, 0x9e, kvm_x86_mce);
    ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, 0x9f, kvm_vcpu_events);
    ioctl_iow_nr!(KVM_SET_VCPU_EVENTS, 0xa0, kvm_vcpu_events);
    ioctl_ior_nr!(KVM_GET_DEBUGREGS, 0xa1, kvm_debugregs);
    ioctl_iow_nr!(KVM_SET_DEBUGREGS, 0xa2, kvm_debugregs);
    ioctl_ior_nr!(KVM_GET_XSAVE, 0xa4, kvm_xsave);
    ioctl_iow_nr!(KVM_SET_XSAVE, 0xa5, kvm_xsave);
    ioctl_ior_nr!(KVM_GET_XCRS, 0xa6, kvm_xcrs);
    ioctl_iowr_nr!(KVM_SET_XCRS, 0xa7, kvm_xcrs);
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod arm {
    // generated with bindgen <arm sysroot>/usr/include/linux/kvm.h --no-unstable-rust --constified-enum '*' -- -I<arm sysroot>/usr/include
    pub mod bindings;
    pub use bindings::*;

    ioctl_iow_nr!(KVM_ARM_SET_DEVICE_ADDR, 0xab, kvm_arm_device_addr);
    ioctl_iow_nr!(KVM_ARM_VCPU_INIT, 0xae, kvm_vcpu_init);
    ioctl_ior_nr!(KVM_ARM_PREFERRED_TARGET, 0xaf, kvm_vcpu_init);
}

// These ioctls are commonly defined on all/multiple platforms.
ioctl_io_nr!(KVM_GET_API_VERSION, 0x00);
ioctl_io_nr!(KVM_CREATE_VM, 0x01);
ioctl_io_nr!(KVM_CHECK_EXTENSION, 0x03);
ioctl_io_nr!(KVM_GET_VCPU_MMAP_SIZE, 0x04) /* in bytes */;
ioctl_iow_nr!(KVM_SET_MEMORY_REGION, 0x40, kvm_memory_region);
ioctl_io_nr!(KVM_CREATE_VCPU, 0x41);
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, 0x42, kvm_dirty_log);
ioctl_io_nr!(KVM_SET_NR_MMU_PAGES, 0x44);
ioctl_io_nr!(KVM_GET_NR_MMU_PAGES, 0x45);
ioctl_iow_nr!(KVM_SET_USER_MEMORY_REGION,0x46, kvm_userspace_memory_region);
ioctl_io_nr!(KVM_SET_TSS_ADDR, 0x47);
ioctl_iow_nr!(KVM_SET_IDENTITY_MAP_ADDR, 0x48, __u64);
ioctl_io_nr!(KVM_CREATE_IRQCHIP, 0x60);
ioctl_iow_nr!(KVM_IRQ_LINE, 0x61, kvm_irq_level);
ioctl_iowr_nr!(KVM_GET_IRQCHIP, 0x62, kvm_irqchip);
ioctl_ior_nr!(KVM_SET_IRQCHIP, 0x63, kvm_irqchip);
ioctl_io_nr!(KVM_CREATE_PIT, 0x64);
ioctl_iowr_nr!(KVM_IRQ_LINE_STATUS, 0x67, kvm_irq_level);
ioctl_iow_nr!(KVM_REGISTER_COALESCED_MMIO, 0x67, kvm_coalesced_mmio_zone);
ioctl_iow_nr!(KVM_UNREGISTER_COALESCED_MMIO, 0x68, kvm_coalesced_mmio_zone);
ioctl_ior_nr!(KVM_ASSIGN_PCI_DEVICE, 0x69,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_ASSIGN_DEV_IRQ, 0x70, kvm_assigned_irq);
ioctl_io_nr!(KVM_REINJECT_CONTROL, 0x71);
ioctl_iow_nr!(KVM_DEASSIGN_PCI_DEVICE, 0x72,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_ASSIGN_SET_MSIX_NR, 0x73,  kvm_assigned_msix_nr);
ioctl_iow_nr!(KVM_ASSIGN_SET_MSIX_ENTRY, 0x74,  kvm_assigned_msix_entry);
ioctl_iow_nr!(KVM_DEASSIGN_DEV_IRQ, 0x75, kvm_assigned_irq);
ioctl_iow_nr!(KVM_IRQFD, 0x76, kvm_irqfd);
ioctl_iow_nr!(KVM_CREATE_PIT2, 0x77, kvm_pit_config);
ioctl_io_nr!(KVM_SET_BOOT_CPU_ID, 0x78);
ioctl_iow_nr!(KVM_IOEVENTFD, 0x79, kvm_ioeventfd);
ioctl_iow_nr!(KVM_SET_CLOCK, 0x7b, kvm_clock_data);
ioctl_ior_nr!(KVM_GET_CLOCK, 0x7c, kvm_clock_data);
ioctl_io_nr!(KVM_SET_TSC_KHZ, 0xa2);
ioctl_io_nr!(KVM_GET_TSC_KHZ, 0xa3);
ioctl_iow_nr!(KVM_ASSIGN_SET_INTX_MASK, 0xa4,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_SIGNAL_MSI, 0xa5, kvm_msi);
ioctl_iowr_nr!(KVM_CREATE_DEVICE, 0xe0, kvm_create_device);
ioctl_iow_nr!(KVM_SET_DEVICE_ATTR, 0xe1, kvm_device_attr);
ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, 0xe2, kvm_device_attr);
ioctl_iow_nr!(KVM_HAS_DEVICE_ATTR, 0xe3, kvm_device_attr);
ioctl_io_nr!(KVM_RUN, 0x80);
// The following two ioctls are commonly defined but specifically excluded
// from arm platforms.
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_ior_nr!(KVM_GET_REGS, 0x81, kvm_regs);
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_iow_nr!(KVM_SET_REGS, 0x82, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, 0x83, kvm_sregs);
ioctl_iow_nr!(KVM_SET_SREGS, 0x84, kvm_sregs);
ioctl_iowr_nr!(KVM_TRANSLATE, 0x85, kvm_translation);
ioctl_iow_nr!(KVM_INTERRUPT, 0x86, kvm_interrupt);
ioctl_iow_nr!(KVM_SET_SIGNAL_MASK, 0x8b, kvm_signal_mask);
ioctl_ior_nr!(KVM_GET_FPU, 0x8c, kvm_fpu);
ioctl_iow_nr!(KVM_SET_FPU, 0x8d, kvm_fpu);
ioctl_iowr_nr!(KVM_TPR_ACCESS_REPORTING, 0x92, kvm_tpr_access_ctl);
ioctl_iow_nr!(KVM_SET_VAPIC_ADDR, 0x93, kvm_vapic_addr);
ioctl_ior_nr!(KVM_GET_MP_STATE, 0x98, kvm_mp_state);
ioctl_iow_nr!(KVM_SET_MP_STATE, 0x99, kvm_mp_state);
ioctl_io_nr!(KVM_NMI, 0x9a);
ioctl_iow_nr!(KVM_SET_GUEST_DEBUG, 0x9b, kvm_guest_debug);
ioctl_iow_nr!(KVM_ENABLE_CAP, 0xa3, kvm_enable_cap);
ioctl_iow_nr!(KVM_DIRTY_TLB, 0xaa, kvm_dirty_tlb);
ioctl_iow_nr!(KVM_GET_ONE_REG, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, 0xac, kvm_one_reg);
ioctl_io_nr!(KVM_KVMCLOCK_CTRL, 0xad);
ioctl_iowr_nr!(KVM_GET_REG_LIST, 0xb0, kvm_reg_list);
ioctl_io_nr!(KVM_SMI, 0xb7);

// Along with the common ioctls, we reexport the ioctls of the current
// platform.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use arm::*;

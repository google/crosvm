// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the HVM (Halla Hypervisor) API.

#![cfg(any(target_os = "android", target_os = "linux"))]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    pub mod bindings;
    use base::ioctl_io_nr;
    use base::ioctl_iow_nr;
    use base::ioctl_iowr_nr;
    pub use bindings::*;

    ioctl_io_nr!(HVM_CREATE_VM, HVM_IOC_MAGIC, 0x01);
    ioctl_io_nr!(HVM_CHECK_EXTENSION, HVM_IOC_MAGIC, 0x02);
    ioctl_iow_nr!(HVM_ENABLE_CAP, HVM_IOC_MAGIC, 0x03, hvm_enable_cap);
    ioctl_iow_nr!(HVM_SET_DTB_CONFIG, HVM_IOC_MAGIC, 0x04, hvm_dtb_config);

    ioctl_io_nr!(HVM_CREATE_VCPU, HVM_IOC_MAGIC, 0x20);
    ioctl_io_nr!(HVM_RUN, HVM_IOC_MAGIC, 0x21);
    ioctl_iow_nr!(HVM_GET_ONE_REG, HVM_IOC_MAGIC, 0x28, hvm_one_reg);
    ioctl_iow_nr!(HVM_SET_ONE_REG, HVM_IOC_MAGIC, 0x29, hvm_one_reg);

    ioctl_iow_nr!(
        HVM_SET_USER_MEMORY_REGION,
        HVM_IOC_MAGIC,
        0x41,
        hvm_userspace_memory_region
    );

    ioctl_iow_nr!(HVM_IRQFD, HVM_IOC_MAGIC, 0x61, hvm_irqfd);
    ioctl_iow_nr!(HVM_IRQ_LINE, HVM_IOC_MAGIC, 0x62, hvm_irq_level);

    ioctl_iowr_nr!(HVM_CREATE_DEVICE, HVM_IOC_MAGIC, 0x80, hvm_create_device);

    ioctl_iow_nr!(HVM_IOEVENTFD, HVM_IOC_MAGIC, 0xa0, hvm_ioeventfd);
}

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

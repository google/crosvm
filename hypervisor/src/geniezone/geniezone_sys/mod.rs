// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the GZVM (Geniezone Hypervisor) API.

#![cfg(unix)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(any(target_arch = "aarch64"))]
pub mod aarch64 {
    pub mod bindings;
    use base::ioctl_io_nr;
    use base::ioctl_iow_nr;
    use base::ioctl_iowr_nr;
    pub use bindings::*;

    ioctl_io_nr!(GZVM_CREATE_VM, GZVM_IOC_MAGIC, 0x01);
    ioctl_io_nr!(GZVM_CHECK_EXTENSION, GZVM_IOC_MAGIC, 0x03);
    ioctl_io_nr!(GZVM_CREATE_VCPU, GZVM_IOC_MAGIC, 0x41);
    ioctl_io_nr!(GZVM_CREATE_IRQCHIP, GZVM_IOC_MAGIC, 0x60);
    ioctl_io_nr!(GZVM_RUN, GZVM_IOC_MAGIC, 0x80);

    ioctl_iow_nr!(
        GZVM_SET_MEMORY_REGION,
        GZVM_IOC_MAGIC,
        0x40,
        gzvm_memory_region
    );

    ioctl_iow_nr!(
        GZVM_SET_USER_MEMORY_REGION,
        GZVM_IOC_MAGIC,
        0x46,
        gzvm_userspace_memory_region
    );

    ioctl_iow_nr!(GZVM_IRQ_LINE, GZVM_IOC_MAGIC, 0x61, gzvm_irq_level);
    ioctl_iow_nr!(GZVM_IRQFD, GZVM_IOC_MAGIC, 0x76, gzvm_irqfd);
    ioctl_iow_nr!(GZVM_IOEVENTFD, GZVM_IOC_MAGIC, 0x79, gzvm_ioeventfd);
    ioctl_iow_nr!(GZVM_ENABLE_CAP, GZVM_IOC_MAGIC, 0xa3, gzvm_enable_cap);
    ioctl_iow_nr!(GZVM_GET_ONE_REG, GZVM_IOC_MAGIC, 0xab, gzvm_one_reg);
    ioctl_iow_nr!(GZVM_SET_ONE_REG, GZVM_IOC_MAGIC, 0xac, gzvm_one_reg);

    ioctl_iowr_nr!(GZVM_CREATE_DEVICE, GZVM_IOC_MAGIC, 0xe0, gzvm_create_device);
}

#[cfg(any(target_arch = "aarch64"))]
pub use aarch64::*;

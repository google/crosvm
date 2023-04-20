// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the Linux Gunyah API.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use base::ioctl_io_nr;
use base::ioctl_iow_nr;

// generated with gunyah_sys/bindgen.sh
pub mod bindings;
pub use bindings::*;

// These ioctls are commonly defined on all/multiple platforms.
ioctl_io_nr!(GH_CREATE_VM, GH_IOCTL_TYPE, 0x0);
ioctl_iow_nr!(
    GH_VM_SET_USER_MEM_REGION,
    GH_IOCTL_TYPE,
    0x1,
    gh_userspace_memory_region
);
ioctl_iow_nr!(GH_VM_SET_DTB_CONFIG, GH_IOCTL_TYPE, 0x2, gh_vm_dtb_config);
ioctl_io_nr!(GH_VM_START, GH_IOCTL_TYPE, 0x3);
ioctl_iow_nr!(GH_VM_ADD_FUNCTION, GH_IOCTL_TYPE, 0x4, gh_fn_desc);
ioctl_io_nr!(GH_VCPU_RUN, GH_IOCTL_TYPE, 0x5);
ioctl_io_nr!(GH_VCPU_MMAP_SIZE, GH_IOCTL_TYPE, 0x6);
ioctl_iow_nr!(GH_VM_REMOVE_FUNCTION, GH_IOCTL_TYPE, 0x7, gh_fn_desc);

// Special bindings for Android Common Kernel
pub const GH_ANDROID_IOCTL_TYPE: u8 = 65u8;
ioctl_iow_nr!(
    GH_VM_ANDROID_LEND_USER_MEM,
    GH_ANDROID_IOCTL_TYPE,
    0x11,
    gh_userspace_memory_region
);
ioctl_iow_nr!(
    GH_VM_ANDROID_SET_FW_CONFIG,
    GH_ANDROID_IOCTL_TYPE,
    0x12,
    gh_vm_firmware_config
);

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::raw::c_char;
use std::os::raw::c_int;

use base::errno_result;
use base::Error;
use base::FromRawDescriptor;
use base::MappedRegion;
use base::Result;
use base::SafeDescriptor;
use libc::open64;
use libc::EBUSY;
use libc::O_CLOEXEC;
use libc::O_RDWR;

use super::haxm_sys::hax_tunnel;
use super::HaxmVcpu;
use super::HAX_EXIT_PAUSED;

pub(super) fn open_haxm_device(_use_ghaxm: bool) -> Result<SafeDescriptor> {
    // Open calls are safe because we give a constant nul-terminated string and verify the
    // result.
    let ret = unsafe { open64("/dev/HAX\0".as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vm_device(_use_ghaxm: bool, vm_id: u32) -> Result<SafeDescriptor> {
    // Haxm creates additional device paths when VMs are created
    let path = format!("/dev/hax_vm/vm{:02}\0", vm_id);

    let ret = unsafe { open64(path.as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }

    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vcpu_device(
    _use_ghaxm: bool,
    vm_id: u32,
    vcpu_id: u32,
) -> Result<SafeDescriptor> {
    // Haxm creates additional device paths when VMs are created
    let path = format!("/dev/hax_vm{:02}/vcpu{:02}\0", vm_id, vcpu_id);

    let ret = unsafe { open64(path.as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
    if ret < 0 {
        return errno_result();
    }

    // Safe because we verify that ret is valid and we own the fd.
    unsafe { SafeDescriptor::from_raw_descriptor(ret) };
}

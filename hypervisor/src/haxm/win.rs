// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_int;
use std::ptr::null_mut;

use base::errno_result;
use base::Error;
use base::FromRawDescriptor;
use base::Result;
use base::SafeDescriptor;
use libc::EBUSY;
use win_util::win32_wide_string;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::CREATE_ALWAYS;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::FILE_ATTRIBUTE_NORMAL;
use winapi::um::winnt::GENERIC_READ;
use winapi::um::winnt::GENERIC_WRITE;

use super::HaxmVcpu;
use crate::VcpuRunHandle;

pub(super) fn open_haxm_device(use_ghaxm: bool) -> Result<SafeDescriptor> {
    // Open calls are safe because we give a constant nul-terminated string and verify the
    // result.
    let ret = unsafe {
        CreateFileW(
            win32_wide_string(if use_ghaxm {
                "\\\\.\\GHAX"
            } else {
                "\\\\.\\HAX"
            })
            .as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if ret == INVALID_HANDLE_VALUE {
        return errno_result();
    }
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vm_device(use_ghaxm: bool, vm_id: u32) -> Result<SafeDescriptor> {
    let name = if use_ghaxm {
        format!("\\\\.\\ghax_vm{:02}", vm_id)
    } else {
        format!("\\\\.\\hax_vm{:02}", vm_id)
    };
    // Open calls are safe because we give a constant nul-terminated string and verify the
    // result.
    let ret = unsafe {
        CreateFileW(
            win32_wide_string(&name).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if ret == INVALID_HANDLE_VALUE {
        return errno_result();
    }
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vcpu_device(
    use_ghaxm: bool,
    vm_id: u32,
    vcpu_id: u32,
) -> Result<SafeDescriptor> {
    let name = if use_ghaxm {
        format!("\\\\.\\ghax_vm{:02}_vcpu{:02}", vm_id, vcpu_id)
    } else {
        format!("\\\\.\\hax_vm{:02}_vcpu{:02}", vm_id, vcpu_id)
    };
    // Open calls are safe because we give a constant nul-terminated string and verify the
    // result.
    let ret = unsafe {
        CreateFileW(
            win32_wide_string(&name).as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };

    if ret == INVALID_HANDLE_VALUE {
        return errno_result();
    }
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

// Returns a new run handle, or Err if one has already been taken for this vcpu.  We do not have a
// windows signal handler, so there's nothing else to do and the run handle drop is a no-op.
pub(super) fn take_run_handle(
    vcpu: &HaxmVcpu,
    _signal_num: Option<c_int>,
) -> Result<VcpuRunHandle> {
    fn vcpu_run_handle_drop() {}

    let vcpu_run_handle = VcpuRunHandle::new(vcpu_run_handle_drop);

    // AcqRel ordering is sufficient to ensure only one thread gets to set its fingerprint to
    // this Vcpu and subsequent `run` calls will see the fingerprint.
    if vcpu
        .vcpu_run_handle_fingerprint
        .compare_exchange(
            0,
            vcpu_run_handle.fingerprint().as_u64(),
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_err()
    {
        // Prevent `vcpu_run_handle_drop` from being called.
        std::mem::forget(vcpu_run_handle);
        return Err(Error::new(EBUSY));
    }

    Ok(vcpu_run_handle)
}

// We do not have a windows signal handler, so for now this function does
// nothing.
pub(super) fn set_local_immediate_exit(_exit: bool) {}

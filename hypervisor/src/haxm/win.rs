// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ptr::null_mut;

use base::errno_result;
use base::FromRawDescriptor;
use base::Result;
use base::SafeDescriptor;
use win_util::win32_wide_string;
use winapi::um::fileapi::CreateFileW;
use winapi::um::fileapi::CREATE_ALWAYS;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::FILE_ATTRIBUTE_NORMAL;
use winapi::um::winnt::GENERIC_READ;
use winapi::um::winnt::GENERIC_WRITE;

pub(super) fn open_haxm_device(use_ghaxm: bool) -> Result<SafeDescriptor> {
    // SAFETY:
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
    // SAFETY:
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

pub(super) fn open_haxm_vm_device(use_ghaxm: bool, vm_id: u32) -> Result<SafeDescriptor> {
    let name = if use_ghaxm {
        format!("\\\\.\\ghax_vm{:02}", vm_id)
    } else {
        format!("\\\\.\\hax_vm{:02}", vm_id)
    };
    // SAFETY:
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
    // SAFETY:
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
    // SAFETY:
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
    // SAFETY:
    // Safe because we verify that ret is valid and we own the fd.
    Ok(unsafe { SafeDescriptor::from_raw_descriptor(ret) })
}

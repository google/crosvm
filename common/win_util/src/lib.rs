// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Library for common Windows-specfic utilities
//!
//! TODO(b/223723424) win_util should be merged into win_sys_util or part of the
//! base.

// Do nothing on unix as win_util is windows only.
#![cfg(windows)]

mod large_integer;
pub use crate::large_integer::*;

mod security_attributes;
pub use crate::security_attributes::*;

use libc::c_ulong;
use std::ffi::{CString, OsStr};
use std::iter::once;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::slice;
use std::sync::Once;
use std::{io, ptr};
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::handleapi::{
    CloseHandle, DuplicateHandle, SetHandleInformation, INVALID_HANDLE_VALUE,
};
use winapi::um::minwinbase::STILL_ACTIVE;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, ResumeThread,
};
use winapi::um::sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO};
use winapi::um::winbase::{CreateFileMappingA, HANDLE_FLAG_INHERIT};
use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, HRESULT, PROCESS_DUP_HANDLE};

#[macro_export]
macro_rules! syscall_bail {
    ($details:expr) => {
        ::anyhow::bail!(
            "{} (Error code {})",
            $details,
            ::winapi::um::errhandlingapi::GetLastError()
        )
    };
}

/// Returns the lower 32 bits of a u64 as a u32 (c_ulong/DWORD)
pub fn get_low_order(number: u64) -> c_ulong {
    (number & (u32::max_value() as u64)) as c_ulong
}

/// Returns the upper 32 bits of a u64 as a u32 (c_ulong/DWORD)
pub fn get_high_order(number: u64) -> c_ulong {
    (number >> 32) as c_ulong
}

static INIT_NATIVE_SYSTEM_INFO: Once = Once::new();
static mut NATIVE_SYSTEM_INFO: MaybeUninit<SYSTEM_INFO> = MaybeUninit::uninit();

pub fn pagesize() -> usize {
    get_native_system_info().dwPageSize as usize
}

pub fn allocation_granularity() -> u64 {
    get_native_system_info().dwAllocationGranularity as u64
}

pub fn number_of_processors() -> usize {
    get_native_system_info().dwNumberOfProcessors as usize
}

fn get_native_system_info() -> SYSTEM_INFO {
    INIT_NATIVE_SYSTEM_INFO.call_once(|| unsafe {
        // Safe because this is a universally available call on modern Windows systems.
        GetNativeSystemInfo(NATIVE_SYSTEM_INFO.as_mut_ptr());
    });
    // Safe because it is guaranteed to be initialized by GetNativeSystemInfo above.
    unsafe { NATIVE_SYSTEM_INFO.assume_init() }
}

pub fn win32_string(value: &str) -> CString {
    CString::new(value).unwrap()
}

pub fn win32_wide_string(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

/// Returns the length, in u16 words (*not* UTF-16 chars), of a null-terminated u16 string.
/// Safe when `wide` is non-null and points to a u16 string terminated by a null character.
unsafe fn strlen_ptr_u16(wide: *const u16) -> usize {
    assert!(!wide.is_null());
    for i in 0.. {
        if *wide.offset(i) == 0 {
            return i as usize;
        }
    }
    unreachable!()
}

/// Converts a UTF-16 null-terminated string to an owned `String`.  Any invalid code points are
/// converted to `std::char::REPLACEMENT_CHARACTER`.
/// Safe when `wide` is non-null and points to a u16 string terminated by a null character.
pub unsafe fn from_ptr_win32_wide_string(wide: *const u16) -> String {
    assert!(!wide.is_null());
    let len = strlen_ptr_u16(wide);
    let slice = slice::from_raw_parts(wide, len);
    String::from_utf16_lossy(slice)
}

pub fn duplicate_handle_with_target_pid(hndl: RawHandle, target_pid: u32) -> io::Result<RawHandle> {
    // Safe because caller will guarentee `hndl` and `target_pid` are valid and won't be dropped.
    unsafe {
        let target_process_handle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, target_pid);
        if target_process_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let result = duplicate_handle_with_target_handle(hndl, target_process_handle);
        CloseHandle(target_process_handle);
        result
    }
}

pub fn duplicate_handle_from_source_process(
    source_process_handle: RawHandle,
    hndl: RawHandle,
    target_process_handle: RawHandle,
) -> io::Result<RawHandle> {
    // Safe because:
    // 1. We are checking the return code
    // 2. new_handle_ptr points to a valid location on the stack
    // 3. Caller guarantees hndl is a real valid handle.
    unsafe {
        let mut new_handle: RawHandle = ptr::null_mut();
        let success_flag = DuplicateHandle(
            /* hSourceProcessHandle= */ source_process_handle,
            /* hSourceHandle= */ hndl,
            /* hTargetProcessHandle= */ target_process_handle,
            /* lpTargetHandle= */ &mut new_handle,
            /* dwDesiredAccess= */ 0,
            /* bInheritHandle= */ TRUE,
            /* dwOptions= */ DUPLICATE_SAME_ACCESS,
        );

        if success_flag == FALSE {
            Err(io::Error::last_os_error())
        } else {
            Ok(new_handle)
        }
    }
}

fn duplicate_handle_with_target_handle(
    hndl: RawHandle,
    target_process_handle: RawHandle,
) -> io::Result<RawHandle> {
    // Safe because `GetCurrentProcess` just gets the current process handle.
    duplicate_handle_from_source_process(
        unsafe { GetCurrentProcess() },
        hndl,
        target_process_handle,
    )
}

pub fn duplicate_handle(hndl: RawHandle) -> io::Result<RawHandle> {
    // Safe because `GetCurrentProcess` just gets the current process handle.
    duplicate_handle_with_target_handle(hndl, unsafe { GetCurrentProcess() })
}

/// Sets whether a handle is inheritable. Note that this only works on some types of handles,
/// such as files, pipes, etc. See
/// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation#parameters
/// for further details.
pub fn set_handle_inheritance(hndl: RawHandle, inheritable: bool) -> io::Result<()> {
    // Safe because even if hndl is invalid, no unsafe memory access will result.
    let res = unsafe {
        SetHandleInformation(
            hndl,
            HANDLE_FLAG_INHERIT,
            if inheritable { HANDLE_FLAG_INHERIT } else { 0 },
        )
    };
    if res == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Rusty version of CreateFileMappingA.
///
/// # Safety
/// If provided, the caller must ensure hndl is valid.
pub unsafe fn create_file_mapping(
    handle: Option<RawHandle>,
    size: u64,
    protection: DWORD,
    name: Option<&str>,
) -> io::Result<RawHandle> {
    let name_cstr = name.map(|s| CString::new(s).unwrap());
    let name = name_cstr.map(|n| n.as_ptr()).unwrap_or(ptr::null_mut());

    // Safe because:
    // 1. The caller guarantees handle is valid (if provided).
    // 2. The C string is guaranteed valid.
    // 3. We check the results of the call.
    let mapping_handle = CreateFileMappingA(
        match handle {
            Some(h) => h,
            None => INVALID_HANDLE_VALUE,
        },
        SecurityAttributes::new_with_security_descriptor(
            SelfRelativeSecurityDescriptor::get_singleton(),
            /* inherit= */ true,
        )
        .as_mut(),
        protection,
        get_high_order(size),
        get_low_order(size),
        name,
    );

    if mapping_handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(mapping_handle)
    }
}

#[derive(PartialEq)]
pub enum ThreadState {
    // The specified thread was not suspended.
    NotSuspended,
    // The specified thread was suspended, but was restarted.
    Restarted,
    // The specified thread is still suspended.
    StillSuspended,
}

/// Decrements a thread's suspend count. When the suspend count reaches 0, the
/// thread is resumed. Returned `ThreadState` indicates whether the thread was
/// resumed.
pub fn resume_thread(handle: RawHandle) -> io::Result<ThreadState> {
    // Safe as even an invalid handle should cause no adverse effects.
    match unsafe { ResumeThread(handle) } {
        u32::MAX => Err(io::Error::last_os_error()),
        0 => Ok(ThreadState::NotSuspended),
        1 => Ok(ThreadState::Restarted),
        _ => Ok(ThreadState::StillSuspended),
    }
}

/// Retrieves the termination status of the specified process.
pub fn get_exit_code_process(handle: RawHandle) -> io::Result<Option<DWORD>> {
    let mut exit_code: DWORD = 0;
    // Safe as even an invalid handle should cause no adverse effects.
    match unsafe { GetExitCodeProcess(handle, &mut exit_code) } {
        0 => Err(io::Error::last_os_error()),
        _ => {
            if exit_code == STILL_ACTIVE {
                Ok(None)
            } else {
                Ok(Some(exit_code))
            }
        }
    }
}

pub type HResult<T> = Result<T, HRESULT>;

// windows-rs bindings
#[cfg(target_env = "msvc")]
mod bindings {
    ::windows::include_bindings!();
}
#[cfg(target_env = "msvc")]
pub use bindings::Windows::Win32::Globalization::ImmDisableIME;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_low_order_utilities() {
        let some_number: u64 = 0xA3200500FFB40123;
        let high_order: u64 = get_high_order(some_number).into();
        let low_order: u64 = get_low_order(some_number).into();
        assert_eq!(some_number, (high_order << 32) + low_order);
    }

    #[test]
    fn strlen() {
        let u16s = [0];
        assert_eq!(unsafe { strlen_ptr_u16((&u16s).as_ptr()) }, 0);
        let u16s = [
            0xD834, 0xDD1E, 0x006d, 0x0075, 0x0073, 0xDD1E, 0x0069, 0x0063, 0xD834, 0,
        ];
        assert_eq!(unsafe { strlen_ptr_u16((&u16s).as_ptr()) }, 9);
    }

    #[test]
    fn from_win32_wide_string() {
        let u16s = [0];
        assert_eq!(unsafe { from_ptr_win32_wide_string((&u16s).as_ptr()) }, "");
        let u16s = [
            0xD834, 0xDD1E, 0x006d, 0x0075, 0x0073, 0xDD1E, 0x0069, 0x0063, 0xD834, 0,
        ];
        assert_eq!(
            unsafe { from_ptr_win32_wide_string((&u16s).as_ptr()) },
            "𝄞mus�ic�"
        );
    }
}

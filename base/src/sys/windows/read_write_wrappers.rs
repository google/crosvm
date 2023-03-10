// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::LPCVOID;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::um::fileapi::ReadFile;
use winapi::um::fileapi::WriteFile;
use winapi::um::minwinbase::OVERLAPPED;

use crate::AsRawDescriptor;

/// Safety requirements:
/// 1. buf points to memory that will not be freed until the write operation completes.
/// 2. buf points to at least buf_len bytes.
pub unsafe fn write_file(
    handle: &dyn AsRawDescriptor,
    buf: *const u8,
    buf_len: usize,
    overlapped: Option<&mut OVERLAPPED>,
) -> io::Result<usize> {
    let is_overlapped = overlapped.is_some();

    // Safe because buf points to a valid region of memory whose size we have computed,
    // pipe has not been closed (as it's managed by this object), and we check the return
    // value for any errors
    let mut bytes_written: DWORD = 0;
    let success_flag = WriteFile(
        handle.as_raw_descriptor(),
        buf as LPCVOID,
        buf_len
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        match overlapped {
            Some(_) => std::ptr::null_mut(),
            None => &mut bytes_written,
        },
        match overlapped {
            Some(v) => v,
            None => std::ptr::null_mut(),
        },
    );

    if success_flag == 0 {
        let err = io::Error::last_os_error();
        if Some(ERROR_IO_PENDING as i32) == err.raw_os_error() && is_overlapped {
            Ok(0)
        } else {
            Err(err)
        }
    } else {
        Ok(bytes_written as usize)
    }
}

/// Safety requirements:
/// 1. buf points to memory that will not be freed until the read operation completes.
/// 2. buf points to at least buf_len bytes.
pub unsafe fn read_file(
    handle: &dyn AsRawDescriptor,
    buf: *mut u8,
    buf_len: usize,
    overlapped: Option<&mut OVERLAPPED>,
) -> io::Result<usize> {
    // Used to verify if ERROR_IO_PENDING should be an error.
    let is_overlapped = overlapped.is_some();

    // Safe because we cap the size of the read to the size of the buffer
    // and check the return code
    let mut bytes_read: DWORD = 0;
    let success_flag = ReadFile(
        handle.as_raw_descriptor(),
        buf as LPVOID,
        buf_len as DWORD,
        match overlapped {
            Some(_) => std::ptr::null_mut(),
            None => &mut bytes_read,
        },
        match overlapped {
            Some(v) => v,
            None => std::ptr::null_mut(),
        },
    );

    if success_flag == 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            // ERROR_IO_PENDING, according the to docs, isn't really an error. This just means
            // that the ReadFile operation hasn't completed. In this case,
            // `get_overlapped_result` will wait until the operation is completed.
            Some(error_code) if error_code == ERROR_IO_PENDING as i32 && is_overlapped => Ok(0),
            _ => Err(e),
        }
    } else {
        Ok(bytes_read as usize)
    }
}

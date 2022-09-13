// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::io;

pub use winapi::um::winioctl::FSCTL_SET_SPARSE;

use crate::descriptor::AsRawDescriptor;

/// Marks the given file as sparse. Required if we want hole punching to be performant.
/// (If a file is not marked as sparse, a hole punch will just write zeros.)
/// # Safety
///    handle *must* be File. We accept all AsRawDescriptors for convenience.
pub fn set_sparse_file<T: AsRawDescriptor>(handle: &T) -> io::Result<()> {
    // Safe because we check the return value and handle is guaranteed to be a
    // valid file handle by the caller.
    let result = unsafe {
        super::super::ioctl::ioctl_with_ptr(
            handle,
            FSCTL_SET_SPARSE,
            std::ptr::null_mut() as *mut c_void,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    Ok(())
}

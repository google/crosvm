// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::io::Error;

use win_util::LargeInteger;
pub use winapi::um::winioctl::FSCTL_SET_ZERO_DATA;
use winapi::um::winnt::LARGE_INTEGER;

// This struct is not implemented in the winapi so we need to implement it ourselves
#[repr(C)]
#[allow(non_snake_case)] // to match win32 naming api.
#[allow(non_camel_case_types)]
struct FILE_ZERO_DATA_INFORMATION {
    FileOffset: LARGE_INTEGER,
    BeyondFinalZero: LARGE_INTEGER,
}

pub(crate) fn file_punch_hole(handle: &File, offset: u64, length: u64) -> io::Result<()> {
    let large_offset = if offset > std::i64::MAX as u64 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    } else {
        LargeInteger::new(offset as i64)
    };

    if (offset + length) > std::i64::MAX as u64 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }

    let end_offset = LargeInteger::new((offset + length) as i64);

    let zero_data = FILE_ZERO_DATA_INFORMATION {
        FileOffset: *large_offset,
        BeyondFinalZero: *end_offset,
    };

    // SAFETY:
    // Safe because we check the return value and all values should be set
    let result = unsafe { super::ioctl::ioctl_with_ref(handle, FSCTL_SET_ZERO_DATA, &zero_data) };

    if result != 0 {
        return Err(Error::from_raw_os_error(result));
    }

    Ok(())
}

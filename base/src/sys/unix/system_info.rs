// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::sysconf;
use libc::_SC_IOV_MAX;
use libc::_SC_NPROCESSORS_CONF;
use libc::_SC_PAGESIZE;

use crate::errno_result;
use crate::Result;

// Comes from UIO_MAXIOV in "uio.h"
const IOV_MAX_DEFAULT: usize = 1024;

/// Safe wrapper for `sysconf(_SC_IOV_MAX)`.
#[inline(always)]
pub fn iov_max() -> usize {
    // SAFETY:
    // Trivially safe
    let iov_max = unsafe { sysconf(_SC_IOV_MAX) };
    if iov_max < 0 {
        IOV_MAX_DEFAULT
    } else {
        iov_max as usize
    }
}

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // SAFETY:
    // Trivially safe
    // man sysconf says return value "Must not be less than 1."
    let pagesize = unsafe { sysconf(_SC_PAGESIZE) };
    if pagesize <= 0 {
        panic!("Error reading system page size, got invalid value.");
    }
    pagesize as usize
}

/// Returns the number of online logical cores on the system.
#[inline(always)]
pub fn number_of_logical_cores() -> Result<usize> {
    // SAFETY:
    // Safe because we pass a flag for this call and the host supports this system call
    let nprocs_conf = unsafe { sysconf(_SC_NPROCESSORS_CONF) };
    if nprocs_conf < 0 {
        errno_result()
    } else {
        Ok(nprocs_conf as usize)
    }
}

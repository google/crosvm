// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::sysconf;
use libc::_SC_IOV_MAX;
use libc::_SC_NPROCESSORS_CONF;
use libc::_SC_PAGESIZE;

use crate::Result;

/// Safe wrapper for `sysconf(_SC_IOV_MAX)`.
#[inline(always)]
pub fn iov_max() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_IOV_MAX) as usize }
}

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Returns the number of online logical cores on the system.
#[inline(always)]
pub fn number_of_logical_cores() -> Result<usize> {
    // Safe because we pass a flag for this call and the host supports this system call
    Ok(unsafe { sysconf(_SC_NPROCESSORS_CONF) } as usize)
}

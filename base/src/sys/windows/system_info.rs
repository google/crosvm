// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;

use once_cell::sync::Lazy;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::sysinfoapi::GetNativeSystemInfo;
use winapi::um::sysinfoapi::SYSTEM_INFO;

use super::Pid;
use crate::Result;

struct SystemInfo {
    pagesize: usize,
    number_of_logical_cores: usize,
    allocation_granularity: u64,
}

static SYSTEM_INFO: Lazy<SystemInfo> = Lazy::new(|| {
    // Safe because this is a universally available call on modern Windows systems.
    let sysinfo = unsafe {
        let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetNativeSystemInfo(sysinfo.as_mut_ptr());
        sysinfo.assume_init()
    };

    SystemInfo {
        pagesize: sysinfo.dwPageSize as usize,
        number_of_logical_cores: sysinfo.dwNumberOfProcessors as usize,
        allocation_granularity: sysinfo.dwAllocationGranularity.into(),
    }
});

/// Returns the system page size in bytes.
pub fn pagesize() -> usize {
    SYSTEM_INFO.pagesize
}

/// Returns the number of online logical cores on the system.
pub fn number_of_logical_cores() -> Result<usize> {
    Ok(SYSTEM_INFO.number_of_logical_cores)
}

/// Returns the minimum memory allocation granularity in bytes.
pub fn allocation_granularity() -> u64 {
    SYSTEM_INFO.allocation_granularity
}

/// Cross-platform wrapper around getting the current process id.
#[inline(always)]
pub fn getpid() -> Pid {
    // Safe because we only use the return value. ProcessId can safely be converted from DWORD to i32.
    unsafe { GetCurrentProcessId() as Pid }
}

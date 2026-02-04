// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;
use std::sync::LazyLock;

use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::sysinfoapi::GetNativeSystemInfo;
use winapi::um::sysinfoapi::SYSTEM_INFO;

use super::Pid;
use crate::Result;

struct SystemInfo {
    pagesize: usize,
    number_of_logical_cores: usize,
    number_of_online_cores: usize,
    allocation_granularity: u64,
}

static SYSTEM_INFO: LazyLock<SystemInfo> = LazyLock::new(|| {
    // SAFETY:
    // Safe because this is a universally available call on modern Windows systems.
    let sysinfo = unsafe {
        let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetNativeSystemInfo(sysinfo.as_mut_ptr());
        sysinfo.assume_init()
    };

    SystemInfo {
        pagesize: sysinfo.dwPageSize as usize,
        number_of_logical_cores: sysinfo.dwNumberOfProcessors as usize,
        // For Windows, the concept of "online" cores doesn't exist in the same way as in Linux.
        // Cores can be considered "parked", invisible/inaccessible to the VM, disabled, or unused;
        // but it's technically different from online vs offline. Assume all cores are online for
        // simplicity.
        number_of_online_cores: sysinfo.dwNumberOfProcessors as usize,
        allocation_granularity: sysinfo.dwAllocationGranularity.into(),
    }
});

/// Returns the system page size in bytes.
pub fn pagesize() -> usize {
    SYSTEM_INFO.pagesize
}

/// Returns the number of logical cores on the system.
pub fn number_of_logical_cores() -> Result<usize> {
    Ok(SYSTEM_INFO.number_of_logical_cores)
}

/// Returns the number of online cores on the system.
pub fn number_of_online_cores() -> Result<usize> {
    Ok(SYSTEM_INFO.number_of_online_cores)
}

/// Returns the minimum memory allocation granularity in bytes.
pub fn allocation_granularity() -> u64 {
    SYSTEM_INFO.allocation_granularity
}

/// Cross-platform wrapper around getting the current process id.
#[inline(always)]
pub fn getpid() -> Pid {
    // SAFETY:
    // Safe because we only use the return value.
    unsafe { GetCurrentProcessId() }
}

/// Set the name of the thread.
pub fn set_thread_name(_name: &str) -> Result<()> {
    todo!();
}

/// Returns a bool if the CPU is online, or an error if there was an issue reading the system
/// properties.
pub fn is_cpu_online(_cpu_id: usize) -> Result<bool> {
    // See SYSTEM_INFO.number_of_online_cores for more context.
    Ok(true)
}

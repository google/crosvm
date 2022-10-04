// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::EINVAL;
use winapi::um::processthreadsapi::GetCurrentThread;
use winapi::um::winbase::SetThreadAffinityMask;

use super::errno_result;
use super::Error;
use super::Result;

/// Set the CPU affinity of the current thread to a given set of CPUs.
/// The cpus must be a subset of those in the process affinity mask.
/// If there are more than 64 processors, the affinity mask must specify
/// processors in the thread's current processor group.
///
/// Returns the previous bits set for cpu_affinity.
/// # Examples
///
/// Set the calling thread's CPU affinity so it will run on only CPUs
/// 0, 1, 5, and 6.
///
/// ```
/// # use base::platform::set_cpu_affinity;
///   set_cpu_affinity(vec![0, 1, 5, 6]).unwrap();
/// ```
pub fn set_cpu_affinity<I: IntoIterator<Item = usize>>(cpus: I) -> Result<usize> {
    let mut affinity_mask: usize = 0;
    for cpu in cpus {
        if cpu >= 64 {
            return Err(Error::new(EINVAL));
        }
        affinity_mask |= 1 << cpu;
    }
    set_cpu_affinity_mask(affinity_mask)
}

pub fn set_cpu_affinity_mask(affinity_mask: usize) -> Result<usize> {
    let res: usize = unsafe {
        let thread_handle = GetCurrentThread();
        SetThreadAffinityMask(thread_handle, affinity_mask)
    };
    if res == 0 {
        return errno_result::<usize>();
    }
    Ok(res)
}

pub fn get_cpu_affinity() -> Result<Vec<usize>> {
    // Unimplemented for now, since this is unused on Windows.  Thread affinity can be read by
    // calling GetThreadAffinityMask twice, to get and restore the previous affinities.
    Err(Error::new(EINVAL))
}

#[cfg(test)]
mod tests {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winbase::GetProcessAffinityMask;

    use super::super::sched::*;
    #[test]
    fn cpu_affinity() {
        let mut process_affinity_mask: usize = 0;
        let mut system_affinity_mask: usize = 0;
        let res = unsafe {
            GetProcessAffinityMask(
                GetCurrentProcess(),
                &mut process_affinity_mask as *mut usize,
                &mut system_affinity_mask as *mut usize,
            )
        };
        assert_ne!(res, 0);
        let mut prev_thread_affinity = set_cpu_affinity(vec![0, 1]).unwrap();
        assert_eq!(process_affinity_mask, prev_thread_affinity);
        // reset to original process affinity and grab previous affinity.
        prev_thread_affinity = set_cpu_affinity_mask(process_affinity_mask).unwrap();
        // cpu 0 + cpu 1, means bit 0 and bit 1 are set (1 + 2 = 3). Verify that is the case.
        assert_eq!(prev_thread_affinity, 3);
    }
}

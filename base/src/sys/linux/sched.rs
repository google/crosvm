// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wrappers for CPU affinity functions.

use std::iter::FromIterator;
use std::mem;

use libc::cpu_set_t;
use libc::prctl;
use libc::sched_getaffinity;
use libc::sched_setaffinity;
use libc::CPU_ISSET;
use libc::CPU_SET;
use libc::CPU_SETSIZE;
use libc::CPU_ZERO;
use libc::EINVAL;

use super::Error;
use super::Result;

// This is needed because otherwise the compiler will complain that the
// impl doesn't reference any types from inside this crate.
struct CpuSet(cpu_set_t);

impl CpuSet {
    pub fn new() -> CpuSet {
        // cpu_set_t is a C struct and can be safely initialized with zeroed memory.
        let mut cpuset: cpu_set_t = unsafe { mem::MaybeUninit::zeroed().assume_init() };
        // Safe because we pass a valid cpuset pointer.
        unsafe { CPU_ZERO(&mut cpuset) };
        CpuSet(cpuset)
    }

    pub fn to_cpus(&self) -> Vec<usize> {
        let mut cpus = Vec::new();
        for i in 0..(CPU_SETSIZE as usize) {
            if unsafe { CPU_ISSET(i, &self.0) } {
                cpus.push(i);
            }
        }
        cpus
    }
}

impl FromIterator<usize> for CpuSet {
    fn from_iter<I: IntoIterator<Item = usize>>(cpus: I) -> Self {
        let mut cpuset = CpuSet::new();
        for cpu in cpus {
            // Safe because we pass a valid cpu index and cpuset.0 is a valid pointer.
            unsafe { CPU_SET(cpu, &mut cpuset.0) };
        }
        cpuset
    }
}

/// Set the CPU affinity of the current thread to a given set of CPUs.
///
/// # Examples
///
/// Set the calling thread's CPU affinity so it will run on only CPUs
/// 0, 1, 5, and 6.
///
/// ```
/// # use base::platform::set_cpu_affinity;
///   set_cpu_affinity(vec![0, 1, 5, 6]).unwrap();
/// ```
pub fn set_cpu_affinity<I: IntoIterator<Item = usize>>(cpus: I) -> Result<()> {
    let CpuSet(cpuset) = cpus
        .into_iter()
        .map(|cpu| {
            if cpu < CPU_SETSIZE as usize {
                Ok(cpu)
            } else {
                Err(Error::new(EINVAL))
            }
        })
        .collect::<Result<CpuSet>>()?;

    // Safe because we pass 0 for the current thread, and cpuset is a valid pointer and only
    // used for the duration of this call.
    crate::syscall!(unsafe { sched_setaffinity(0, mem::size_of_val(&cpuset), &cpuset) })?;

    Ok(())
}

pub fn get_cpu_affinity() -> Result<Vec<usize>> {
    let mut cpu_set = CpuSet::new();

    // Safe because we pass 0 for the current thread, and cpu_set.0 is a valid pointer and only
    // used for the duration of this call.
    crate::syscall!(unsafe { sched_getaffinity(0, mem::size_of_val(&cpu_set.0), &mut cpu_set.0) })?;

    Ok(cpu_set.to_cpus())
}

/// Enable experimental core scheduling for the current thread.
///
/// If successful, the kernel should not schedule this thread with any other thread within the same
/// SMT core. Because this is experimental, this will return success on kernels which do not support
/// this function.
pub fn enable_core_scheduling() -> Result<()> {
    const PR_SCHED_CORE: i32 = 62;
    const PR_SCHED_CORE_CREATE: i32 = 1;

    #[allow(clippy::upper_case_acronyms, non_camel_case_types, dead_code)]
    /// Specifies the scope of the pid parameter of `PR_SCHED_CORE`.
    enum pid_type {
        /// `PID` refers to threads.
        PIDTYPE_PID,
        /// `TGPID` refers to a process.
        PIDTYPE_TGID,
        /// `TGPID` refers to a process group.
        PIDTYPE_PGID,
    }

    let ret = unsafe {
        prctl(
            PR_SCHED_CORE,
            PR_SCHED_CORE_CREATE,
            0,                            // id of target task, 0 indicates current task
            pid_type::PIDTYPE_PID as i32, // PID scopes to this thread only
            0,                            // ignored by PR_SCHED_CORE_CREATE command
        )
    };
    if ret == -1 {
        let error = Error::last();
        // prctl returns EINVAL for unknown functions, which we will ignore for now.
        if error.errno() != libc::EINVAL {
            return Err(error);
        }
    }
    Ok(())
}

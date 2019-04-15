// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wrappers for CPU affinity functions.

use std::iter::FromIterator;
use std::mem;

use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_SETSIZE, CPU_ZERO, EINVAL};

use crate::{errno_result, Error, Result};

// This is needed because otherwise the compiler will complain that the
// impl doesn't reference any types from inside this crate.
struct CpuSet(cpu_set_t);

impl FromIterator<usize> for CpuSet {
    fn from_iter<I: IntoIterator<Item = usize>>(cpus: I) -> Self {
        // cpu_set_t is a C struct and can be safely initialized with zeroed memory.
        let mut cpuset: cpu_set_t = unsafe { mem::zeroed() };
        // Safe because we pass a valid cpuset pointer.
        unsafe { CPU_ZERO(&mut cpuset) };
        for cpu in cpus {
            // Safe because we pass a valid cpuset pointer and cpu index.
            unsafe { CPU_SET(cpu, &mut cpuset) };
        }
        CpuSet(cpuset)
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
/// # use sys_util::set_cpu_affinity;
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
    let res = unsafe { sched_setaffinity(0, mem::size_of_val(&cpuset), &cpuset) };

    if res != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

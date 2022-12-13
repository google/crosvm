// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;

use super::errno_result;
use super::Result;

/// Enables real time thread priorities in the current thread up to `limit`.
pub fn set_rt_prio_limit(limit: u64) -> Result<()> {
    let rt_limit_arg = libc::rlimit64 {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // Safe because the kernel doesn't modify memory that is accessible to the process here.
    let res = unsafe { libc::setrlimit64(libc::RLIMIT_RTPRIO, &rt_limit_arg) };

    if res != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// Sets the current thread to be scheduled using the round robin real time class with `priority`.
pub fn set_rt_round_robin(priority: i32) -> Result<()> {
    // Safe because sched_param only contains primitive types for which zero
    // initialization is valid.
    let mut sched_param: libc::sched_param = unsafe { MaybeUninit::zeroed().assume_init() };
    sched_param.sched_priority = priority;

    // Safe because the kernel doesn't modify memory that is accessible to the process here.
    let res =
        unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_RR, &sched_param) };

    if res != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

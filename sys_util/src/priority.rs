// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{errno_result, Result};

/// Enables real time thread priorities in the current thread up to `limit`.
pub fn set_rt_prio_limit(limit: u64) -> Result<()> {
    let rt_limit_arg = libc::rlimit {
        rlim_cur: limit as libc::rlim_t,
        rlim_max: limit as libc::rlim_t,
    };
    // Safe because the kernel doesn't modify memory that is accessible to the process here.
    let res = unsafe { libc::setrlimit(libc::RLIMIT_RTPRIO, &rt_limit_arg) };

    if res != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

/// Sets the current thread to be scheduled using the round robin real time class with `priority`.
pub fn set_rt_round_robin(priority: i32) -> Result<()> {
    let sched_param = libc::sched_param {
        sched_priority: priority,
    };

    // Safe because the kernel doesn't modify memory that is accessible to the process here.
    let res =
        unsafe { libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_RR, &sched_param) };

    if res != 0 {
        errno_result()
    } else {
        Ok(())
    }
}

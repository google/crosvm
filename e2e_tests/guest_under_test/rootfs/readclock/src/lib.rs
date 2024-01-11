// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A helper binary for reading CLOCK_BOOTTIME and CLOCK_MONOTONIC
//! to verify the virtio-pvclock behavior.
//! This program is used by corresponding e2e_tests.

use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clock_gettime_nanos(clock_id: i32) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: This is safe since clock_gettime will succeed always
    // and will not break Rust's assumption on data structures
    // because it is called with valid parameters.
    assert_eq!(unsafe { libc::clock_gettime(clock_id, &mut ts) }, 0);
    ts.tv_sec as u64 * 1_000_000_000u64 + ts.tv_nsec as u64
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clock_monotonic_now() -> Duration {
    Duration::from_nanos(clock_gettime_nanos(libc::CLOCK_MONOTONIC))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clock_boottime_now() -> Duration {
    Duration::from_nanos(clock_gettime_nanos(libc::CLOCK_BOOTTIME))
}

/// ClockValues hold the values read out from the kernel
/// via clock_gettime syscall.
#[derive(Serialize, Deserialize, Debug)]
pub struct ClockValues {
    pub clock_monotonic: Duration,
    pub clock_boottime: Duration,
}
impl ClockValues {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn now() -> Self {
        Self {
            clock_monotonic: clock_monotonic_now(),
            clock_boottime: clock_boottime_now(),
        }
    }
    pub fn clock_monotonic(&self) -> Duration {
        self.clock_monotonic
    }
    pub fn clock_boottime(&self) -> Duration {
        self.clock_boottime
    }
}

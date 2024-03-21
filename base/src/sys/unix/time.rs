// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use libc::timespec;

/// Return a timespec filed with the specified Duration `duration`.
#[allow(clippy::useless_conversion)]
pub fn duration_to_timespec(duration: Duration) -> timespec {
    // nsec always fits in i32 because subsec_nanos is defined to be less than one billion.
    let nsec = duration.subsec_nanos() as i32;
    timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: nsec.into(),
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{gmtime_s, time_t, tm};

/// # Safety
/// safe because we are passing in the allocated tm struct
/// for the operating system to fill in.
pub unsafe fn gmtime_secure(now: *const time_t, result: *mut tm) {
    gmtime_s(result, now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn gmtime() {
        // Safe because struct is not used before being initialized
        // by gmtime_secure.
        let mut tm: tm = unsafe { mem::zeroed() };
        let time_12_11_2019_noonish_pst = 1576094579;
        unsafe {
            gmtime_secure(&time_12_11_2019_noonish_pst, &mut tm);
        }
        assert_eq!(tm.tm_sec, 59);
        assert_eq!(tm.tm_min, 2);
        assert_eq!(tm.tm_hour, 20);
        assert_eq!(tm.tm_mday, 11);
        assert_eq!(tm.tm_mon, 11);
        assert_eq!(tm.tm_year, 119);
        assert_eq!(tm.tm_wday, 3);
        assert_eq!(tm.tm_yday, 344);
        assert_eq!(tm.tm_isdst, 0);
    }
}

// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{c_int, c_void};

use crate::{errno_result, Result};

#[allow(non_camel_case_types)]
type cap_t = *mut c_void;

#[link(name = "cap")]
extern "C" {
    fn cap_init() -> cap_t;
    fn cap_free(ptr: *mut c_void) -> c_int;
    fn cap_set_proc(cap: cap_t) -> c_int;
}

/// Drops all capabilities (permitted, inheritable, and effective) from the current process.
pub fn drop_capabilities() -> Result<()> {
    unsafe {
        // Safe because we do not actually manipulate any memory handled by libcap
        // and we check errors.
        let caps = cap_init();
        if caps.is_null() {
            return errno_result();
        }

        // Freshly initialized capabilities do not have any bits set, so applying them
        // will drop all capabilities from the process.
        // Safe because we will check the result and otherwise do not touch the memory.
        let ret = cap_set_proc(caps);
        // We need to free capabilities regardless of success of the operation above.
        cap_free(caps);
        // Now check if we managed to apply (drop) capabilities.
        if ret < 0 {
            return errno_result();
        }
    }
    Ok(())
}

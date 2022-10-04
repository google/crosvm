// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;

use anyhow::anyhow;
use anyhow::Result;

use crate::bindings;

/// Wrapper over `VAStatus`, calling check() returns a Error if the status is not VA_STATUS_SUCCESS.
#[must_use = "VAStatus might not be VA_STATUS_SUCCESS."]
pub(crate) struct Status(pub bindings::VAStatus);

impl Status {
    /// Returns `Ok(())` if this status is successful, and an error otherwise.
    pub(crate) fn check(&self) -> Result<()> {
        if self.0 == bindings::constants::VA_STATUS_SUCCESS as i32 {
            Ok(())
        } else {
            // Safe because `vaErrorStr` will return a pointer to a statically allocated, null
            // terminated C string. The pointer is guaranteed to never be null.
            let err_str = unsafe { CStr::from_ptr(bindings::vaErrorStr(self.0)) }
                .to_str()
                .unwrap();
            Err(anyhow!("VA-API error: {}: {}", self.0, err_str))
        }
    }
}

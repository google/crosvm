// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::bindings;
use crate::error::*;
use crate::format::*;

/// Represents an input video format for VDA.
pub struct InputFormat {
    pub profile: Profile,
    pub min_width: u32,
    pub min_height: u32,
    pub max_width: u32,
    pub max_height: u32,
}

impl InputFormat {
    pub(crate) fn new(f: &bindings::vda_input_format_t) -> Result<InputFormat> {
        let profile = Profile::n(f.profile).ok_or(Error::UnknownProfile(f.profile))?;

        Ok(InputFormat {
            profile,
            min_width: f.min_width,
            min_height: f.min_height,
            max_width: f.max_width,
            max_height: f.max_height,
        })
    }

    // The callers must guarantee that `data` is valid for |`len`| elements when
    // both `data` and `len` are valid.
    pub(crate) unsafe fn from_raw_parts(
        data: *const bindings::vda_input_format_t,
        len: usize,
    ) -> Result<Vec<Self>> {
        validate_formats(data, len, Self::new)
    }
}

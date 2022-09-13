// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use enumn::N;

use super::bindings;
use crate::error::Result;
use crate::format::*;

/// Represents an output profile for VEA.
#[derive(Debug, Clone, Copy)]
pub struct OutputProfile {
    pub profile: Profile,
    pub max_width: u32,
    pub max_height: u32,
    pub max_framerate_numerator: u32,
    pub max_framerate_denominator: u32,
}

impl OutputProfile {
    pub(crate) fn new(p: &bindings::vea_profile_t) -> Result<Self> {
        Ok(Self {
            profile: Profile::new(p.profile)?,
            max_width: p.max_width,
            max_height: p.max_height,
            max_framerate_numerator: p.max_framerate_numerator,
            max_framerate_denominator: p.max_framerate_denominator,
        })
    }

    pub(crate) unsafe fn from_raw_parts(
        data: *const bindings::vea_profile_t,
        len: usize,
    ) -> Result<Vec<Self>> {
        validate_formats(data, len, Self::new)
    }
}

/// Represents a bitrate mode for the VEA.
#[derive(Debug, Clone, Copy, N)]
#[repr(u32)]
pub enum BitrateMode {
    VBR = bindings::vea_bitrate_mode_VBR,
    CBR = bindings::vea_bitrate_mode_CBR,
}

/// Represents a bitrate for the VEA.
#[derive(Debug, Clone, Copy)]
pub struct Bitrate {
    pub mode: BitrateMode,
    pub target: u32,
    pub peak: u32,
}

impl Bitrate {
    pub fn to_raw_bitrate(&self) -> bindings::vea_bitrate_t {
        bindings::vea_bitrate_t {
            mode: match self.mode {
                BitrateMode::VBR => bindings::vea_bitrate_mode_VBR,
                BitrateMode::CBR => bindings::vea_bitrate_mode_CBR,
            },
            target: self.target,
            peak: self.peak,
        }
    }
}

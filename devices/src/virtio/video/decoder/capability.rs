// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Capablities of the virtio video decoder device.

use std::collections::BTreeMap;

use crate::virtio::video::control::*;
use crate::virtio::video::format::*;

#[derive(Clone)]
pub struct Capability {
    in_fmts: Vec<FormatDesc>,
    out_fmts: Vec<FormatDesc>,

    // Stores supporterd profiles and levels for each format.
    profiles: BTreeMap<Format, Vec<Profile>>,
    levels: BTreeMap<Format, Vec<Level>>,
}

impl Capability {
    // Make this method pub(super) so backends can create capabilities.
    pub(super) fn new(
        in_fmts: Vec<FormatDesc>,
        out_fmts: Vec<FormatDesc>,
        profiles: BTreeMap<Format, Vec<Profile>>,
        levels: BTreeMap<Format, Vec<Level>>,
    ) -> Self {
        Self {
            in_fmts,
            out_fmts,
            profiles,
            levels,
        }
    }

    pub fn input_formats(&self) -> &Vec<FormatDesc> {
        &self.in_fmts
    }

    pub fn output_formats(&self) -> &Vec<FormatDesc> {
        &self.out_fmts
    }

    pub fn query_control(&self, t: &QueryCtrlType) -> Option<QueryCtrlResponse> {
        use QueryCtrlType::*;
        match *t {
            Profile(fmt) => {
                let profiles = self.profiles.get(&fmt)?;
                Some(QueryCtrlResponse::Profile(profiles.to_vec()))
            }
            Level(fmt) => {
                let levels = self.levels.get(&fmt)?;
                Some(QueryCtrlResponse::Level(levels.to_vec()))
            }
        }
    }
}

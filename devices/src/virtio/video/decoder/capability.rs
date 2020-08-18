// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Capablities of the virtio video decoder device.

use base::warn;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use crate::virtio::video::control::*;
use crate::virtio::video::format::*;

fn from_pixel_format(
    fmt: &libvda::PixelFormat,
    mask: u64,
    width_range: FormatRange,
    height_range: FormatRange,
) -> FormatDesc {
    let format = match fmt {
        libvda::PixelFormat::NV12 => Format::NV12,
        libvda::PixelFormat::YV12 => Format::YUV420,
    };

    let frame_formats = vec![FrameFormat {
        width: width_range,
        height: height_range,
        bitrates: Vec::new(),
    }];

    FormatDesc {
        mask,
        format,
        frame_formats,
    }
}

pub struct Capability {
    pub in_fmts: Vec<FormatDesc>,
    pub out_fmts: Vec<FormatDesc>,

    // Stores supporterd profiles and levels for each format.
    profiles: BTreeMap<Format, Vec<Profile>>,
    levels: BTreeMap<Format, Vec<Level>>,
}

impl Capability {
    pub fn new(caps: &libvda::decode::Capabilities) -> Self {
        // Raise the first |# of supported raw formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.output_formats.len());

        let mut in_fmts = vec![];
        let mut profiles: BTreeMap<Format, Vec<Profile>> = Default::default();
        for fmt in caps.input_formats.iter() {
            match Profile::from_libvda_profile(fmt.profile) {
                Some(profile) => {
                    let format = profile.to_format();
                    in_fmts.push(FormatDesc {
                        mask,
                        format,
                        frame_formats: vec![Default::default()],
                    });
                    match profiles.entry(format) {
                        Entry::Occupied(mut e) => e.get_mut().push(profile),
                        Entry::Vacant(e) => {
                            e.insert(vec![profile]);
                        }
                    }
                }
                None => {
                    warn!(
                        "No virtio-video equivalent for libvda profile, skipping: {:?}",
                        fmt.profile
                    );
                }
            }
        }

        let levels: BTreeMap<Format, Vec<Level>> = if profiles.contains_key(&Format::H264) {
            // We only support Level 1.0 for H.264.
            vec![(Format::H264, vec![Level::H264_1_0])]
                .into_iter()
                .collect()
        } else {
            Default::default()
        };

        // Prepare {min, max} of {width, height}.
        // While these values are associated with each input format in libvda,
        // they are associated with each output format in virtio-video protocol.
        // Thus, we compute max of min values and min of max values here.
        let min_width = caps.input_formats.iter().map(|fmt| fmt.min_width).max();
        let max_width = caps.input_formats.iter().map(|fmt| fmt.max_width).min();
        let min_height = caps.input_formats.iter().map(|fmt| fmt.min_height).max();
        let max_height = caps.input_formats.iter().map(|fmt| fmt.max_height).min();
        let width_range = FormatRange {
            min: min_width.unwrap_or(0),
            max: max_width.unwrap_or(0),
            step: 1,
        };
        let height_range = FormatRange {
            min: min_height.unwrap_or(0),
            max: max_height.unwrap_or(0),
            step: 1,
        };

        // Raise the first |# of supported coded formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.input_formats.len());
        let out_fmts = caps
            .output_formats
            .iter()
            .map(|fmt| from_pixel_format(fmt, mask, width_range, height_range))
            .collect();

        Capability {
            in_fmts,
            out_fmts,
            profiles,
            levels,
        }
    }

    pub fn query_control(&self, t: &QueryCtrlType) -> Option<QueryCtrlResponse> {
        use QueryCtrlType::*;
        match *t {
            Profile(fmt) => {
                let profiles = self.profiles.get(&fmt)?;
                Some(QueryCtrlResponse::Profile(
                    profiles.iter().copied().collect(),
                ))
            }
            Level(fmt) => {
                let levels = self.levels.get(&fmt)?;
                Some(QueryCtrlResponse::Level(levels.iter().copied().collect()))
            }
        }
    }
}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of data structures for virtio-video controls.

use std::convert::From;
use std::io;

use data_model::Le32;

use crate::virtio::video::format::BitrateMode;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::Profile;
use crate::virtio::video::protocol::*;
use crate::virtio::video::response::Response;
use crate::virtio::Writer;

#[derive(Debug)]
pub enum QueryCtrlType {
    Profile(Format),
    Level(Format),
}

#[derive(Debug, Clone)]
pub enum QueryCtrlResponse {
    Profile(Vec<Profile>),
    #[allow(dead_code)]
    Level(Vec<Level>),
}

impl Response for QueryCtrlResponse {
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        match self {
            QueryCtrlResponse::Profile(ps) => {
                w.write_obj(virtio_video_query_control_resp_profile {
                    num: Le32::from(ps.len() as u32),
                    ..Default::default()
                })?;
                w.write_iter(ps.iter().map(|p| Le32::from(*p as u32)))
            }
            QueryCtrlResponse::Level(ls) => {
                w.write_obj(virtio_video_query_control_resp_level {
                    num: Le32::from(ls.len() as u32),
                    ..Default::default()
                })?;
                w.write_iter(ls.iter().map(|l| Le32::from(*l as u32)))
            }
        }
    }
}

#[derive(Debug)]
pub enum CtrlType {
    Bitrate,
    Profile,
    Level,
    ForceKeyframe,
    BitrateMode,
    BitratePeak,
    PrependSpsPpsToIdr,
}

#[derive(Debug, Clone)]
pub enum CtrlVal {
    Bitrate(u32),
    Profile(Profile),
    Level(Level),
    ForceKeyframe,
    BitrateMode(BitrateMode),
    BitratePeak(u32),
    PrependSpsPpsToIdr(bool),
}

impl Response for CtrlVal {
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        match self {
            CtrlVal::Bitrate(r) => w.write_obj(virtio_video_control_val_bitrate {
                bitrate: Le32::from(*r),
                ..Default::default()
            }),
            CtrlVal::BitratePeak(r) => w.write_obj(virtio_video_control_val_bitrate_peak {
                bitrate_peak: Le32::from(*r),
                ..Default::default()
            }),
            CtrlVal::BitrateMode(m) => w.write_obj(virtio_video_control_val_bitrate_mode {
                bitrate_mode: Le32::from(*m as u32),
                ..Default::default()
            }),
            CtrlVal::Profile(p) => w.write_obj(virtio_video_control_val_profile {
                profile: Le32::from(*p as u32),
                ..Default::default()
            }),
            CtrlVal::Level(l) => w.write_obj(virtio_video_control_val_level {
                level: Le32::from(*l as u32),
                ..Default::default()
            }),
            CtrlVal::ForceKeyframe => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Button controls should not be queried.",
            )),
            CtrlVal::PrependSpsPpsToIdr(p) => {
                w.write_obj(virtio_video_control_val_prepend_spspps_to_idr {
                    prepend_spspps_to_idr: Le32::from(*p as u32),
                    ..Default::default()
                })
            }
        }
    }
}

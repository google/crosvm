// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures for commands of virtio video devices.

use std::io;

use data_model::{Le32, Le64};

use crate::virtio::video::command::QueueType;
use crate::virtio::video::control::*;
use crate::virtio::video::format::*;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol::*;
use crate::virtio::Writer;

pub trait Response {
    /// Writes an object to virtqueue.
    fn write(&self, w: &mut Writer) -> Result<(), io::Error>;
}

/// A response to a `VideoCmd`. These correspond to `VIRTIO_VIDEO_RESP_*`.
#[derive(Debug)]
pub enum CmdResponse {
    NoData,
    QueryCapability(Vec<FormatDesc>),
    ResourceQueue {
        timestamp: u64,
        flags: u32,
        size: u32,
    },
    GetParams {
        queue_type: QueueType,
        params: Params,
    },
    QueryControl(QueryCtrlResponse),
    GetControl(CtrlVal),
}

impl Response for CmdResponse {
    /// Writes a response to virtqueue.
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        use CmdResponse::*;

        let type_ = Le32::from(match self {
            NoData => VIRTIO_VIDEO_RESP_OK_NODATA,
            QueryCapability(_) => VIRTIO_VIDEO_RESP_OK_QUERY_CAPABILITY,
            ResourceQueue { .. } => VIRTIO_VIDEO_RESP_OK_RESOURCE_QUEUE,
            GetParams { .. } => VIRTIO_VIDEO_RESP_OK_GET_PARAMS,
            QueryControl(_) => VIRTIO_VIDEO_RESP_OK_QUERY_CONTROL,
            GetControl(_) => VIRTIO_VIDEO_RESP_OK_GET_CONTROL,
        });

        let hdr = virtio_video_cmd_hdr {
            type_,
            ..Default::default()
        };

        match self {
            NoData => w.write_obj(hdr),
            QueryCapability(descs) => {
                w.write_obj(virtio_video_query_capability_resp {
                    hdr,
                    num_descs: Le32::from(descs.len() as u32),
                    ..Default::default()
                })?;
                descs.iter().map(|d| d.write(w)).collect()
            }
            ResourceQueue {
                timestamp,
                flags,
                size,
            } => w.write_obj(virtio_video_resource_queue_resp {
                hdr,
                timestamp: Le64::from(*timestamp),
                flags: Le32::from(*flags),
                size: Le32::from(*size),
            }),
            GetParams { queue_type, params } => {
                let params = params.to_virtio_video_params(*queue_type);
                w.write_obj(virtio_video_get_params_resp { hdr, params })
            }
            QueryControl(r) => {
                w.write_obj(virtio_video_query_control_resp { hdr })?;
                r.write(w)
            }
            GetControl(val) => {
                w.write_obj(virtio_video_get_control_resp { hdr })?;
                val.write(w)
            }
        }
    }
}

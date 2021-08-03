// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures for commands of virtio video devices.

use std::convert::{TryFrom, TryInto};
use std::io;
use thiserror::Error as ThisError;

use base::error;
use data_model::Le32;
use enumn::N;

use crate::virtio::video::control::*;
use crate::virtio::video::format::*;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol::*;
use crate::virtio::Reader;

/// An error indicating a failure while reading a request from the guest.
#[derive(Debug, ThisError)]
pub enum ReadCmdError {
    /// Failed to read an object.
    #[error("failed to read object: {0}")]
    IoError(#[from] io::Error),
    /// Invalid argument is passed.
    #[error("invalid argument passed to command")]
    InvalidArgument,
    /// The type of the command was invalid.
    #[error("invalid command type: {0}")]
    InvalidCmdType(u32),
    /// The type of the requested control was unsupported.
    #[error("unsupported control type: {0}")]
    UnsupportedCtrlType(u32),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
pub enum QueueType {
    Input = VIRTIO_VIDEO_QUEUE_TYPE_INPUT,
    Output = VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT,
}
impl_try_from_le32_for_enumn!(QueueType, "queue_type");

#[derive(Debug)]
pub enum VideoCmd {
    QueryCapability {
        queue_type: QueueType,
    },
    StreamCreate {
        stream_id: u32,
        coded_format: Format,
    },
    StreamDestroy {
        stream_id: u32,
    },
    StreamDrain {
        stream_id: u32,
    },
    ResourceCreate {
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
        plane_offsets: Vec<u32>,
        uuid: u128,
    },
    ResourceQueue {
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
        timestamp: u64,
        data_sizes: Vec<u32>,
    },
    ResourceDestroyAll {
        stream_id: u32,
        queue_type: QueueType,
    },
    QueueClear {
        stream_id: u32,
        queue_type: QueueType,
    },
    GetParams {
        stream_id: u32,
        queue_type: QueueType,
    },
    SetParams {
        stream_id: u32,
        queue_type: QueueType,
        params: Params,
    },
    QueryControl {
        query_ctrl_type: QueryCtrlType,
    },
    GetControl {
        stream_id: u32,
        ctrl_type: CtrlType,
    },
    SetControl {
        stream_id: u32,
        ctrl_val: CtrlVal,
    },
}

impl<'a> VideoCmd {
    /// Reads a request on virtqueue and construct a VideoCmd value.
    pub fn from_reader(r: &'a mut Reader) -> Result<Self, ReadCmdError> {
        use self::ReadCmdError::*;
        use self::VideoCmd::*;

        // Unlike structs in virtio_video.h in the kernel, our command structs in protocol.rs don't
        // have a field of `struct virtio_video_cmd_hdr`. So, we first read the header here and
        // a body below.
        let hdr = r.read_obj::<virtio_video_cmd_hdr>()?;

        Ok(match hdr.type_.into() {
            VIRTIO_VIDEO_CMD_QUERY_CAPABILITY => {
                let virtio_video_query_capability { queue_type, .. } = r.read_obj()?;
                QueryCapability {
                    queue_type: queue_type.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_CREATE => {
                let virtio_video_stream_create {
                    in_mem_type,
                    out_mem_type,
                    coded_format,
                    ..
                } = r.read_obj()?;

                if in_mem_type != VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT
                    || out_mem_type != VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT
                {
                    error!("mem_type must be VIRTIO_OBJECT");
                    return Err(InvalidArgument);
                }
                StreamCreate {
                    stream_id: hdr.stream_id.into(),
                    coded_format: coded_format.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_DESTROY => {
                let virtio_video_stream_destroy { .. } = r.read_obj()?;
                StreamDestroy {
                    stream_id: hdr.stream_id.into(),
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_DRAIN => {
                let virtio_video_stream_drain { .. } = r.read_obj()?;
                StreamDrain {
                    stream_id: hdr.stream_id.into(),
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_CREATE => {
                let virtio_video_resource_create {
                    queue_type,
                    resource_id,
                    planes_layout,
                    num_planes,
                    plane_offsets,
                    ..
                } = r.read_obj()?;

                // Assume ChromeOS-specific requirements.
                if Into::<u32>::into(planes_layout) != VIRTIO_VIDEO_PLANES_LAYOUT_SINGLE_BUFFER {
                    error!(
                        "each buffer must be a single DMAbuf: {}",
                        Into::<u32>::into(planes_layout),
                    );
                    return Err(InvalidArgument);
                }

                let num_planes: u32 = num_planes.into();
                if num_planes as usize > plane_offsets.len() {
                    error!(
                        "num_planes must not exceed {} but {}",
                        plane_offsets.len(),
                        num_planes
                    );
                    return Err(InvalidArgument);
                }
                let plane_offsets = plane_offsets[0..num_planes as usize]
                    .iter()
                    .map(|x| Into::<u32>::into(*x))
                    .collect::<Vec<u32>>();

                let virtio_video_object_entry { uuid } = r.read_obj()?;

                ResourceCreate {
                    stream_id: hdr.stream_id.into(),
                    queue_type: queue_type.try_into()?,
                    resource_id: resource_id.into(),
                    plane_offsets,
                    uuid: u128::from_be_bytes(uuid),
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_QUEUE => {
                let virtio_video_resource_queue {
                    queue_type,
                    resource_id,
                    timestamp,
                    num_data_sizes,
                    data_sizes,
                    ..
                } = r.read_obj()?;

                let num_data_sizes: u32 = num_data_sizes.into();
                if num_data_sizes as usize > data_sizes.len() {
                    return Err(InvalidArgument);
                }
                let data_sizes = data_sizes[0..num_data_sizes as usize]
                    .iter()
                    .map(|x| Into::<u32>::into(*x))
                    .collect::<Vec<u32>>();
                ResourceQueue {
                    stream_id: hdr.stream_id.into(),
                    queue_type: queue_type.try_into()?,
                    resource_id: resource_id.into(),
                    timestamp: timestamp.into(),
                    data_sizes,
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_DESTROY_ALL => {
                let virtio_video_resource_destroy_all { queue_type, .. } = r.read_obj()?;
                ResourceDestroyAll {
                    stream_id: hdr.stream_id.into(),
                    queue_type: queue_type.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_QUEUE_CLEAR => {
                let virtio_video_queue_clear { queue_type, .. } = r.read_obj()?;
                QueueClear {
                    stream_id: hdr.stream_id.into(),
                    queue_type: queue_type.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_GET_PARAMS => {
                let virtio_video_get_params { queue_type, .. } = r.read_obj()?;
                GetParams {
                    stream_id: hdr.stream_id.into(),
                    queue_type: queue_type.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_SET_PARAMS => {
                let virtio_video_set_params { params } = r.read_obj()?;
                SetParams {
                    stream_id: hdr.stream_id.into(),
                    queue_type: params.queue_type.try_into()?,
                    params: params.try_into()?,
                }
            }
            VIRTIO_VIDEO_CMD_QUERY_CONTROL => {
                let body = r.read_obj::<virtio_video_query_control>()?;
                let query_ctrl_type = match body.control.into() {
                    VIRTIO_VIDEO_CONTROL_PROFILE => QueryCtrlType::Profile(
                        r.read_obj::<virtio_video_query_control_profile>()?
                            .format
                            .try_into()?,
                    ),
                    VIRTIO_VIDEO_CONTROL_LEVEL => QueryCtrlType::Level(
                        r.read_obj::<virtio_video_query_control_level>()?
                            .format
                            .try_into()?,
                    ),
                    t => {
                        return Err(ReadCmdError::UnsupportedCtrlType(t));
                    }
                };
                QueryControl { query_ctrl_type }
            }
            VIRTIO_VIDEO_CMD_GET_CONTROL => {
                let virtio_video_get_control { control, .. } = r.read_obj()?;
                let ctrl_type = match control.into() {
                    VIRTIO_VIDEO_CONTROL_BITRATE => CtrlType::Bitrate,
                    VIRTIO_VIDEO_CONTROL_BITRATE_PEAK => CtrlType::BitratePeak,
                    VIRTIO_VIDEO_CONTROL_BITRATE_MODE => CtrlType::BitrateMode,
                    VIRTIO_VIDEO_CONTROL_PROFILE => CtrlType::Profile,
                    VIRTIO_VIDEO_CONTROL_LEVEL => CtrlType::Level,
                    VIRTIO_VIDEO_CONTROL_FORCE_KEYFRAME => CtrlType::ForceKeyframe,
                    VIRTIO_VIDEO_CONTROL_PREPEND_SPSPPS_TO_IDR => CtrlType::PrependSpsPpsToIdr,
                    t => {
                        return Err(ReadCmdError::UnsupportedCtrlType(t));
                    }
                };
                GetControl {
                    stream_id: hdr.stream_id.into(),
                    ctrl_type,
                }
            }
            VIRTIO_VIDEO_CMD_SET_CONTROL => {
                let virtio_video_set_control { control, .. } = r.read_obj()?;
                let ctrl_val = match control.into() {
                    VIRTIO_VIDEO_CONTROL_BITRATE => CtrlVal::Bitrate(
                        r.read_obj::<virtio_video_control_val_bitrate>()?
                            .bitrate
                            .into(),
                    ),
                    VIRTIO_VIDEO_CONTROL_BITRATE_PEAK => CtrlVal::BitratePeak(
                        r.read_obj::<virtio_video_control_val_bitrate_peak>()?
                            .bitrate_peak
                            .into(),
                    ),
                    VIRTIO_VIDEO_CONTROL_BITRATE_MODE => CtrlVal::BitrateMode(
                        r.read_obj::<virtio_video_control_val_bitrate_mode>()?
                            .bitrate_mode
                            .try_into()?,
                    ),
                    VIRTIO_VIDEO_CONTROL_PROFILE => CtrlVal::Profile(
                        r.read_obj::<virtio_video_control_val_profile>()?
                            .profile
                            .try_into()?,
                    ),
                    VIRTIO_VIDEO_CONTROL_LEVEL => CtrlVal::Level(
                        r.read_obj::<virtio_video_control_val_level>()?
                            .level
                            .try_into()?,
                    ),
                    VIRTIO_VIDEO_CONTROL_FORCE_KEYFRAME => CtrlVal::ForceKeyframe,
                    VIRTIO_VIDEO_CONTROL_PREPEND_SPSPPS_TO_IDR => CtrlVal::PrependSpsPpsToIdr(
                        r.read_obj::<virtio_video_control_val_prepend_spspps_to_idr>()?
                            .prepend_spspps_to_idr
                            != 0,
                    ),
                    t => {
                        return Err(ReadCmdError::UnsupportedCtrlType(t));
                    }
                };
                SetControl {
                    stream_id: hdr.stream_id.into(),
                    ctrl_val,
                }
            }
            _ => return Err(ReadCmdError::InvalidCmdType(hdr.type_.into())),
        })
    }
}

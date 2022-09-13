// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Parameters for streams in virtio video devices.

use std::convert::From;
use std::convert::Into;
use std::convert::TryFrom;

use base::error;
use data_model::Le32;

use crate::virtio::video::command::QueueType;
use crate::virtio::video::command::ReadCmdError;
use crate::virtio::video::format::*;
use crate::virtio::video::protocol::*;
use crate::virtio::video::resource::ResourceType;

/// Safe wrapper of `virtio_video_params`.
/// Note that this struct doesn't have a field corresponding to `queue_type` in
/// `virtio_video_params`. The type of queue should be stored by one that has an `Params` instance.
#[derive(Debug, Default, Clone)]
pub struct Params {
    // Use `Option<Format>` instead of `Format` because an image format may not be determined until
    // video decoding is started in the decoder.
    pub format: Option<Format>,
    pub resource_type: ResourceType,
    pub frame_width: u32,
    pub frame_height: u32,
    pub min_buffers: u32,
    pub max_buffers: u32,
    pub crop: Crop,
    pub frame_rate: u32,
    pub plane_formats: Vec<PlaneFormat>,
}

impl TryFrom<virtio_video_params> for Params {
    type Error = ReadCmdError;

    fn try_from(
        virtio_video_params {
            format,
            frame_width,
            frame_height,
            min_buffers,
            max_buffers,
            crop,
            frame_rate,
            num_planes,
            plane_formats,
            ..
        }: virtio_video_params,
    ) -> Result<Self, Self::Error> {
        let num_planes = Into::<u32>::into(num_planes); // as usize;
        if num_planes as usize > plane_formats.len() {
            error!(
                "num_planes must not exceed {} but {}",
                plane_formats.len(),
                Into::<u32>::into(num_planes)
            );
            return Err(ReadCmdError::InvalidArgument);
        }
        let plane_formats = plane_formats[0..num_planes as usize]
            .iter()
            .map(|x| Into::<PlaneFormat>::into(*x))
            .collect::<Vec<_>>();

        Ok(Params {
            format: Format::n(format.into()),
            resource_type: Default::default(),
            frame_width: frame_width.into(),
            frame_height: frame_height.into(),
            min_buffers: min_buffers.into(),
            max_buffers: max_buffers.into(),
            crop: crop.into(),
            frame_rate: frame_rate.into(),
            plane_formats,
        })
    }
}

impl TryFrom<virtio_video_params_ext> for Params {
    type Error = ReadCmdError;

    fn try_from(
        virtio_video_params_ext {
            base,
            resource_type,
            ..
        }: virtio_video_params_ext,
    ) -> Result<Self, Self::Error> {
        let mut params = Params::try_from(base)?;
        params.resource_type = match resource_type.into() {
            VIRTIO_VIDEO_MEM_TYPE_GUEST_PAGES => ResourceType::GuestPages,
            VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT => ResourceType::VirtioObject,
            _ => return Err(ReadCmdError::InvalidArgument),
        };

        Ok(params)
    }
}

impl Params {
    pub fn to_virtio_video_params(&self, queue_type: QueueType) -> virtio_video_params {
        let Params {
            format,
            resource_type: _,
            frame_width,
            frame_height,
            min_buffers,
            max_buffers,
            crop,
            frame_rate,
            plane_formats,
        } = self;
        let num_planes = Le32::from(plane_formats.len() as u32);
        let mut p_fmts: [virtio_video_plane_format; VIRTIO_VIDEO_MAX_PLANES as usize] =
            Default::default();
        for (i, pf) in plane_formats.iter().enumerate() {
            p_fmts[i] = Into::<virtio_video_plane_format>::into(*pf);
        }

        virtio_video_params {
            queue_type: (queue_type as u32).into(),
            format: format
                .map(|f| Le32::from(f as u32))
                .unwrap_or_else(|| Le32::from(0)),
            frame_width: Le32::from(*frame_width),
            frame_height: Le32::from(*frame_height),
            min_buffers: Le32::from(*min_buffers),
            max_buffers: Le32::from(*max_buffers),
            crop: virtio_video_crop::from(*crop),
            frame_rate: Le32::from(*frame_rate),
            num_planes,
            plane_formats: p_fmts,
        }
    }

    pub fn to_virtio_video_params_ext(&self, queue_type: QueueType) -> virtio_video_params_ext {
        let Params { resource_type, .. } = self;

        let resource_type = match *resource_type {
            ResourceType::GuestPages => VIRTIO_VIDEO_MEM_TYPE_GUEST_PAGES,
            ResourceType::VirtioObject => VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT,
        };

        virtio_video_params_ext {
            base: self.to_virtio_video_params(queue_type),
            resource_type: Le32::from(resource_type),
            padding: Default::default(),
        }
    }
}

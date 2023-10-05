// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::virtio::device_constants::video::VideoDeviceType;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_video(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
        device_type: VideoDeviceType,
    ) -> Result<VhostUserVirtioDevice> {
        VhostUserVirtioDevice::new(
            connection,
            match device_type {
                VideoDeviceType::Decoder => DeviceType::VideoDec,
                VideoDeviceType::Encoder => DeviceType::VideoEnc,
            },
            max_queue_size,
            base_features,
            None,
        )
    }
}

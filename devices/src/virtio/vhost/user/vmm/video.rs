// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::device_constants::video::all_backend_virtio_features;
use crate::virtio::device_constants::video::VideoDeviceType;
use crate::virtio::device_constants::video::QUEUE_SIZES;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::QueueSizes;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_video(
        base_features: u64,
        connection: Connection,
        device_type: VideoDeviceType,
    ) -> Result<VhostUserVirtioDevice> {
        let queue_sizes = QueueSizes::Fixed(QUEUE_SIZES.to_vec());
        let max_queues = QUEUE_SIZES.len();

        let allow_features = all_backend_virtio_features();

        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;

        VhostUserVirtioDevice::new(
            connection,
            match device_type {
                VideoDeviceType::Decoder => DeviceType::VideoDec,
                VideoDeviceType::Encoder => DeviceType::VideoEnc,
            },
            queue_sizes,
            max_queues,
            allow_features,
            allow_protocol_features,
            base_features,
            None,
            false,
        )
    }
}

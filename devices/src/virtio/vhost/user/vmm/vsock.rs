// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::QueueSizes;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::vhost::vsock;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_vsock(base_features: u64, connection: Connection) -> Result<VhostUserVirtioDevice> {
        let queue_sizes = QueueSizes::AskDevice {
            queue_size: vsock::QUEUE_SIZE,
            default_queues: vsock::QUEUE_SIZES.len(),
        };
        let max_queues = vsock::QUEUE_SIZES.len();

        let allow_features = 0;

        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Vsock,
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

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::QueueSizes;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

const QUEUE_SIZE: u16 = 1024;

// control, event, tx, and rx queues
const NUM_QUEUES: usize = 4;

impl VhostUserVirtioDevice {
    pub fn new_snd(base_features: u64, connection: Connection) -> Result<VhostUserVirtioDevice> {
        let queue_sizes = QueueSizes::AskDevice {
            queue_size: QUEUE_SIZE,
            default_queues: NUM_QUEUES,
        };
        let max_queues = NUM_QUEUES;

        let allow_features = 0;
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Sound,
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

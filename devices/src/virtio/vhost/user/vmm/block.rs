// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_block(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
    ) -> Result<VhostUserVirtioDevice> {
        let default_queues = 1;

        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Block,
            default_queues,
            max_queue_size,
            allow_protocol_features,
            base_features,
            None,
            false,
        )
    }
}

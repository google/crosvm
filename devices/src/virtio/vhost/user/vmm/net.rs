// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_net(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
    ) -> Result<VhostUserVirtioDevice> {
        // 3 = rx, tx, ctrl
        let default_queues = 3;

        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Net,
            default_queues,
            max_queue_size,
            allow_protocol_features,
            base_features,
            None,
            false,
        )
    }
}

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_console(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
    ) -> Result<VhostUserVirtioDevice> {
        // VIRTIO_CONSOLE_F_MULTIPORT is not supported, so we just implement port 0 (receiveq,
        // transmitq)
        let default_queues = 2;

        let allow_features = 0;

        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Console,
            default_queues,
            max_queue_size,
            allow_features,
            allow_protocol_features,
            base_features,
            None,
            false,
        )
    }
}

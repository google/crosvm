// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Console,
            default_queues,
            max_queue_size,
            base_features,
            None,
        )
    }
}

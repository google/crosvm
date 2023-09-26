// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

const QUEUE_COUNT: usize = 2;

impl VhostUserVirtioDevice {
    pub fn new_mac80211_hwsim(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
    ) -> Result<VhostUserVirtioDevice> {
        let default_queues = QUEUE_COUNT;

        let allow_features = 0;

        let allow_protocol_features = VhostUserProtocolFeatures::empty();

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Mac80211HwSim,
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

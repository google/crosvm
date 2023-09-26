// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::device_constants::wl::NUM_QUEUES;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_SEND_FENCES;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_TRANS_FLAGS;
use crate::virtio::device_constants::wl::VIRTIO_WL_F_USE_SHMEM;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_wl(
        base_features: u64,
        connection: Connection,
        max_queue_size: Option<u16>,
    ) -> Result<VhostUserVirtioDevice> {
        let default_queues = NUM_QUEUES;

        let allow_features = 1 << VIRTIO_WL_F_TRANS_FLAGS
            | 1 << VIRTIO_WL_F_SEND_FENCES
            | 1 << VIRTIO_WL_F_USE_SHMEM;

        let allow_protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Wl,
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

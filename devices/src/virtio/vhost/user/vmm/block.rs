// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::device_constants::block::VIRTIO_BLK_F_BLK_SIZE;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_DISCARD;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_FLUSH;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_MQ;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_RO;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_SEG_MAX;
use crate::virtio::device_constants::block::VIRTIO_BLK_F_WRITE_ZEROES;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_block(base_features: u64, connection: Connection) -> Result<VhostUserVirtioDevice> {
        let default_queues = 1;

        let allow_features = 1 << VIRTIO_BLK_F_SEG_MAX
            | 1 << VIRTIO_BLK_F_RO
            | 1 << VIRTIO_BLK_F_BLK_SIZE
            | 1 << VIRTIO_BLK_F_FLUSH
            | 1 << VIRTIO_BLK_F_MQ
            | 1 << VIRTIO_BLK_F_DISCARD
            | 1 << VIRTIO_BLK_F_WRITE_ZEROES;

        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::SLAVE_REQ;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Block,
            default_queues,
            allow_features,
            allow_protocol_features,
            base_features,
            None,
            false,
        )
    }
}

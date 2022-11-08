// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vmm_vhost::message::VhostUserProtocolFeatures;

use crate::virtio::device_constants::gpu;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::QueueSizes;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserVirtioDevice;
use crate::virtio::DeviceType;

impl VhostUserVirtioDevice {
    pub fn new_gpu(base_features: u64, connection: Connection) -> Result<VhostUserVirtioDevice> {
        let queue_sizes = QueueSizes::Fixed(gpu::QUEUE_SIZES.to_vec());
        let max_queues = gpu::QUEUE_SIZES.len();

        let allow_features = 1 << gpu::VIRTIO_GPU_F_VIRGL
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_UUID
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_BLOB
            | 1 << gpu::VIRTIO_GPU_F_CONTEXT_INIT
            | 1 << gpu::VIRTIO_GPU_F_EDID
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_SYNC
            | 1 << gpu::VIRTIO_GPU_F_CREATE_GUEST_HANDLE;

        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::SLAVE_REQ
            | VhostUserProtocolFeatures::SHARED_MEMORY_REGIONS;

        VhostUserVirtioDevice::new(
            connection,
            DeviceType::Gpu,
            queue_sizes,
            max_queues,
            allow_features,
            allow_protocol_features,
            base_features,
            None,
            true,
        )
    }
}

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::Le32;
use virtio_sys::virtio_fs::virtio_fs_config;
use zerocopy::AsBytes;

use crate::virtio::device_constants::fs::FS_MAX_TAG_LEN;
use crate::virtio::vhost_user_frontend::Error;
use crate::virtio::vhost_user_frontend::Result;
use crate::virtio::vhost_user_frontend::VhostUserFrontend;
use crate::virtio::DeviceType;

impl VhostUserFrontend {
    pub fn new_fs(
        base_features: u64,
        connection: vmm_vhost::SystemStream,
        max_queue_size: Option<u16>,
        tag: Option<&str>,
    ) -> Result<VhostUserFrontend> {
        let cfg = if let Some(tag) = tag {
            if tag.len() > FS_MAX_TAG_LEN {
                return Err(Error::TagTooLong {
                    len: tag.len(),
                    max: FS_MAX_TAG_LEN,
                });
            }

            let mut cfg_tag = [0u8; FS_MAX_TAG_LEN];
            cfg_tag[..tag.len()].copy_from_slice(tag.as_bytes());

            Some(
                virtio_fs_config {
                    tag: cfg_tag,
                    // Only count the request queue, exclude the high prio queue
                    num_request_queues: Le32::from(1),
                }
                .as_bytes()
                .to_vec(),
            )
        } else {
            None
        };

        VhostUserFrontend::new_internal(
            connection,
            DeviceType::Fs,
            max_queue_size,
            base_features,
            cfg.as_deref(),
            None, // pci_address
        )
    }
}

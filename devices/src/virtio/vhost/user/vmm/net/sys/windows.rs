// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;

use base::Tube;

use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::net::Net;
use crate::virtio::vhost::user::vmm::net::Result;
use crate::virtio::vhost::user::vmm::net::QUEUE_SIZE;

impl Net {
    pub fn new(base_features: u64, tube: Tube) -> Result<Net> {
        let (allow_features, init_features, allow_protocol_features) =
            Self::get_all_features(base_features);

        let mut handler = VhostUserHandler::new_from_tube(
            tube,
            /* max_queue_num= */ 3,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;

        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, 3 /* rx, tx, ctrl */)?;
        Ok(Net {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

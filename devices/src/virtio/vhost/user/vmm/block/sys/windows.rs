// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;

use base::Tube;

use crate::virtio::vhost::user::vmm::block::{Block, QUEUE_SIZE};
use crate::virtio::vhost::user::vmm::{handler::VhostUserHandler, Result};

impl Block {
    pub fn new(base_features: u64, tube: Tube) -> Result<Block> {
        let (allow_features, init_features, allow_protocol_features) =
            Self::get_all_features(base_features);

        let mut handler = VhostUserHandler::new_from_tube(
            tube,
            /* max_queue_num= */ 1,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;

        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, 1)?;

        Ok(Block {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

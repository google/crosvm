// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::virtio::vhost::user::vmm::block::{Block, QUEUE_SIZE};
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::{handler::VhostUserHandler, Result};

impl Block {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Block> {
        let socket = UnixStream::connect(&socket_path).map_err(Error::SocketConnect)?;

        let (allow_features, init_features, allow_protocol_features) =
            Self::get_all_features(base_features);

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            1, /* queues_num */
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

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::Pin;

use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;

use crate::virtio::vhost::user::device::{
    handler::VhostUserBackend, listener::VhostUserListenerTrait,
};

/// TODO implement this. On Windows the `vhost_user_tube` can be provided through the `path`
/// constructor string, and the future returned by `run_backend` can be listened to alonside the
/// close and exit events.
pub struct VhostUserListener;

impl VhostUserListenerTrait for VhostUserListener {
    fn new(
        path: &str,
        max_num_queues: usize,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        todo!()
    }

    fn run_backend(
        self,
        backend: Box<dyn VhostUserBackend>,
        ex: &Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>>>> {
        todo!()
    }
}

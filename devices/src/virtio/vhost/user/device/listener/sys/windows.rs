// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::Pin;

use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;
use vmm_vhost::VhostUserSlaveReqHandler;

use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::device::handler::VhostUserPlatformOps;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;

/// TODO implement this. On Windows the `vhost_user_tube` can be provided through the `path`
/// constructor string, and the future returned by `run_backend` can be listened to alonside the
/// close and exit events.
pub struct VhostUserListener;

impl VhostUserListenerTrait for VhostUserListener {
    fn new(
        _path: &str,
        _max_num_queues: usize,
        _keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        todo!()
    }

    fn run_req_handler<'e, F>(
        self,
        _handler_builder: F,
        _ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>>
    where
        F: FnOnce(Box<dyn VhostUserPlatformOps>) -> Box<dyn VhostUserSlaveReqHandler> + 'e,
    {
        todo!()
    }
}

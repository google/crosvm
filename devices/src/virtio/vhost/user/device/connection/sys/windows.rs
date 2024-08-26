// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::Pin;

use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;

use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
use crate::virtio::vhost::user::device::handler::VhostUserDevice;

/// TODO implement this. On Windows the `vhost_user_tube` can be provided through the `path`
/// constructor string, and the future returned by `run_backend` can be listened to alonside the
/// close and exit events.
pub struct VhostUserListener;
pub struct VhostUserStream;

impl VhostUserConnectionTrait for VhostUserListener {
    fn run_req_handler<'e>(
        self,
        _handler: Box<dyn vmm_vhost::Backend>,
        _ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        todo!()
    }
}

impl VhostUserConnectionTrait for VhostUserStream {
    fn run_req_handler<'e>(
        self,
        _handler: Box<dyn vmm_vhost::Backend>,
        _ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        todo!()
    }
}

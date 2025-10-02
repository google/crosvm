// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;
use std::any::Any;
use std::pin::Pin;

use cros_async::Executor;
use futures::Future;

use crate::virtio::vhost_user_backend::handler::DeviceRequestHandler;
use crate::virtio::vhost_user_backend::handler::VhostUserDevice;
use crate::virtio::vhost_user_backend::VhostUserDeviceBuilder;
use crate::virtio::vhost_user_backend::VhostUserListener;
use crate::virtio::vhost_user_backend::VhostUserStream;

pub enum BackendConnection {
    Listener(VhostUserListener),
    Stream(VhostUserStream),
}

/// Trait that the platform-specific type `VhostUserConnection` needs to implement. It contains all
/// the methods that are ok to call from non-platform specific code.
pub trait VhostUserConnectionTrait {
    /// Take and return resources owned by the parent process in case of a incoming fork.
    ///
    /// This method needs to be called only if you are going to use the connection in a jailed child
    /// process. In this case, the connection will belong to the child and the parent will drop it,
    /// but the child may lack the rights to drop some resources created at construction time. One
    /// such example is the socket file of a regular vhost-user device, that cannot be dropped by
    /// the child unless it gets extra permissions.
    ///
    /// This method returns an opaque object that, upon being dropped, will free these resources.
    /// That way, the child process does not need extra rights to clear them, and the parent can
    /// drop the connection after forking and just need to keep that object alive until the child
    /// exits to do housekeeping properly.
    ///
    /// The default implementation returns nothing as that's what most connection would need anyway.
    fn take_parent_process_resources(&mut self) -> Option<Box<dyn Any>> {
        None
    }

    /// Returns a `Future` that processes requests for `handler`. The future exits when the
    /// front-end side disconnects or an error occurs.
    fn run_req_handler<'e>(
        self,
        handler: Box<dyn vmm_vhost::Backend>,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>>;

    /// Returns a `Future` that will process requests from `backend` when polled. The future exits
    /// when the front-end side disconnects or an error occurs.
    ///
    /// This is a legacy way to run devices - prefer `run_device`.
    fn run_backend<'e>(
        self,
        backend: impl VhostUserDevice + 'static,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>>
    where
        Self: Sized,
    {
        self.run_req_handler(Box::new(DeviceRequestHandler::new(backend)), ex)
    }

    /// Start processing requests for a `VhostUserDevice` on `connection`. Returns when the
    /// front-end side disconnects or an error occurs.
    fn run_device(self, ex: Executor, device: Box<dyn VhostUserDeviceBuilder>) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        ex.run_until(self.run_req_handler(device.build(&ex).unwrap(), &ex))?
    }
}

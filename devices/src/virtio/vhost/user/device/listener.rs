// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;
use std::any::Any;
use std::pin::Pin;

use anyhow::Context;
use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;
pub use sys::VhostUserListener;

use crate::virtio::vhost::user::device::handler::VhostUserBackend;
use crate::virtio::vhost::user::VhostUserDevice;

/// Trait that the platform-specific type `VhostUserListener` needs to implement. It contains all
/// the methods that are ok to call from non-platform specific code.
pub trait VhostUserListenerTrait {
    /// Creates a VhostUserListener from `path`, which is a platform-specific string describing how
    /// to establish the vhost-user channel. For instance, it can be a path to a socket.
    ///
    /// `max_num_queues` is the maximum number of queues we will supports through this channel.
    /// `keep_rds` is a vector of `RawDescriptor`s to which the descriptors needed for this listener
    /// to operate properly will be added if it is `Some()`.
    fn new(
        path: &str,
        max_num_queues: usize,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<VhostUserListener>;

    /// Take and return resources owned by the parent process in case of a incoming fork.
    ///
    /// This method needs to be called only if you are going to use the listener in a jailed child
    /// process. In this case, the listener will belong to the child and the parent will drop it,
    /// but the child may lack the rights to drop some resources created at construction time. One
    /// such example is the socket file of a regular vhost-user device, that cannot be dropped by
    /// the child unless it gets extra permissions.
    ///
    /// This method returns an opaque object that, upon being dropped, will free these resources.
    /// That way, the child process does not need extra rights to clear them, and the parent can
    /// drop the listener after forking and just need to keep that object alive until the child
    /// exits to do housekeeping properly.
    ///
    /// The default implementation returns nothing as that's what most listeners would need anyway.
    fn take_parent_process_resources(&mut self) -> Option<Box<dyn Any>> {
        None
    }

    /// Returns a `Future` that will process requests from `backend` when polled. The future exits
    /// when the front-end side disconnects or an error occurs.
    fn run_backend(
        self,
        backend: Box<dyn VhostUserBackend>,
        ex: &Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;

    /// Start processing requests for a `VhostUserDevice` on `listener`. Returns when the front-end
    /// side disconnects or an error occurs.
    fn run_device(self, device: Box<dyn VhostUserDevice>) -> anyhow::Result<()>
    where
        Self: Sized,
    {
        let ex = Executor::with_executor_kind(device.executor_kind().unwrap_or_default())
            .context("Failed to create an Executor")?;
        let backend = device.into_backend(&ex)?;

        ex.run_until(self.run_backend(backend, &ex))?
    }
}

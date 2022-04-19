// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;
pub use sys::VhostUserListener;

use std::pin::Pin;

use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;

use crate::virtio::vhost::user::device::handler::VhostUserBackend;

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

    /// Returns a `Future` that will process requests from `backend` when polled. The future exits
    /// when the front-end side disconnects or an error occurs.
    fn run_backend(
        self,
        backend: Box<dyn VhostUserBackend>,
        ex: &Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>>>>;
}

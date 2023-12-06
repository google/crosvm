// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::Pin;

use anyhow::Context;
use base::AsRawDescriptor;
use base::RawDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use futures::Future;
use futures::FutureExt;
use vmm_vhost::connection::socket::SocketListener;
use vmm_vhost::connection::Listener;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandler;

use crate::virtio::vhost::user::device::handler::sys::linux::run_handler;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;

/// On Unix we can listen to a socket.
pub struct VhostUserListener(SocketListener);

impl VhostUserListener {
    /// Creates a new regular vhost-user listener, listening on `path`.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    pub fn new_socket(
        path: &str,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        let listener = SocketListener::new(path, true)?;
        if let Some(rds) = keep_rds {
            rds.push(listener.as_raw_descriptor());
        }

        Ok(VhostUserListener(listener))
    }
}

/// Attaches to an already bound socket via `listener` and handles incoming messages from the
/// VMM, which are dispatched to the device backend via the `VhostUserBackend` trait methods.
async fn run_with_handler(
    mut listener: SocketListener,
    handler: Box<dyn VhostUserSlaveReqHandler>,
    ex: &Executor,
) -> anyhow::Result<()> {
    listener.set_nonblocking(true)?;

    loop {
        // If the listener is not ready on the first call to `accept` and returns `None`, we
        // temporarily convert it into an async I/O source and yield until it signals there is
        // input data awaiting, before trying again.
        match listener
            .accept()
            .context("failed to accept an incoming connection")?
        {
            Some(connection) => {
                let req_handler = SlaveReqHandler::new(connection, handler);
                return run_handler(req_handler, ex).await;
            }
            None => {
                // Nobody is on the other end yet, wait until we get a connection.
                let async_waiter = ex
                    .async_from(AsyncWrapper::new(listener))
                    .context("failed to create async waiter")?;
                async_waiter.wait_readable().await?;

                // Retrieve the listener back so we can use it again.
                listener = async_waiter.into_source().into_inner();
            }
        }
    }
}

impl VhostUserListenerTrait for VhostUserListener {
    /// Create a vhost-user listener from a UNIX domain socket path.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptors that must be preserved for this
    /// listener to keep working after forking.
    fn new(
        path: &str,
        _max_num_queues: usize,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        Self::new_socket(path, keep_rds)
    }

    /// Returns a future that runs a `VhostUserSlaveReqHandler` using this listener.
    ///
    /// `ex` is the executor on which the request handler can schedule its own tasks.
    fn run_req_handler<'e>(
        self,
        handler: Box<dyn VhostUserSlaveReqHandler>,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        async { run_with_handler(self.0, handler, ex).await }.boxed_local()
    }

    fn take_parent_process_resources(&mut self) -> Option<Box<dyn std::any::Any>> {
        self.0.take_resources_for_parent()
    }
}

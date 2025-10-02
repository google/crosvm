// Copyright 2024 The ChromiumOS Authors
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
use vmm_vhost::connection::Listener;
use vmm_vhost::unix::SocketListener;
use vmm_vhost::BackendServer;

use crate::virtio::vhost_user_backend::connection::VhostUserConnectionTrait;
use crate::virtio::vhost_user_backend::handler::sys::linux::run_handler;

/// On Unix we can listen to a socket.
pub struct VhostUserListener(SocketListener);

impl VhostUserListener {
    /// Create a vhost-user listener from a UNIX domain socket path.
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let listener = SocketListener::new(path, true)?;

        Ok(VhostUserListener(listener))
    }
}

impl AsRawDescriptor for VhostUserListener {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

/// Attaches to an already bound socket via `listener` and handles incoming messages from the
/// VMM, which are dispatched to the device backend via the `VhostUserDevice` trait methods.
async fn run_with_handler(
    mut listener: SocketListener,
    handler: Box<dyn vmm_vhost::Backend>,
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
                let req_handler = BackendServer::new(connection, handler);
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

impl VhostUserConnectionTrait for VhostUserListener {
    fn run_req_handler<'e>(
        self,
        handler: Box<dyn vmm_vhost::Backend>,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        async { run_with_handler(self.0, handler, ex).await }.boxed_local()
    }

    fn take_parent_process_resources(&mut self) -> Option<Box<dyn std::any::Any>> {
        self.0.take_resources_for_parent()
    }
}

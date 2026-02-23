// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::net::UnixStream;
use std::pin::Pin;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;
use cros_async::Executor;
use futures::Future;
use futures::FutureExt;
use vmm_vhost::BackendServer;
use vmm_vhost::Connection;

use crate::virtio::vhost_user_backend::connection::VhostUserConnectionTrait;
use crate::virtio::vhost_user_backend::handler::sys::macos::run_handler;

/// Connection from connected socket
pub struct VhostUserStream(UnixStream);

impl VhostUserStream {
    /// Creates a new vhost-user connection from an existing connected socket file descriptor.
    pub fn new_socket_from_fd(socket_fd: RawDescriptor) -> anyhow::Result<Self> {
        // On macOS, we don't have /proc/self/fd, so we duplicate the descriptor directly.
        // SAFETY: The caller guarantees this is a valid socket fd.
        let safe_fd = unsafe { SafeDescriptor::from_raw_descriptor(socket_fd) };
        let stream = UnixStream::from(safe_fd);
        Ok(VhostUserStream(stream))
    }
}

impl VhostUserConnectionTrait for VhostUserStream {
    fn run_req_handler<'e>(
        self,
        handler: Box<dyn vmm_vhost::Backend>,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        async { stream_run_with_handler(self.0, handler, ex).await }.boxed_local()
    }
}

impl AsRawDescriptor for VhostUserStream {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

async fn stream_run_with_handler(
    stream: UnixStream,
    handler: Box<dyn vmm_vhost::Backend>,
    ex: &Executor,
) -> anyhow::Result<()> {
    let req_handler = BackendServer::new(Connection::try_from(stream)?, handler);
    run_handler(req_handler, ex).await
}

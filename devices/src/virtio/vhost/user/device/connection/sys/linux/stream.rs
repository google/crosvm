// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;

use base::safe_descriptor_from_cmdline_fd;
use base::AsRawDescriptor;
use base::RawDescriptor;
use cros_async::Executor;
use futures::Future;
use futures::FutureExt;
use vmm_vhost::BackendServer;
use vmm_vhost::Connection;
use vmm_vhost::Error::SocketFromFdError;

use crate::virtio::vhost::user::device::connection::VhostUserConnectionTrait;
use crate::virtio::vhost::user::device::handler::sys::linux::run_handler;

/// Connection from connected socket
pub struct VhostUserStream(UnixStream);

fn path_is_socket(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => metadata.file_type().is_socket(),
        Err(_) => false, // Assume not a socket if we can't get metadata
    }
}

impl VhostUserStream {
    /// Creates a new vhost-user listener from an existing connected socket file descriptor.
    ///
    /// `keep_rds` can be specified to retrieve the raw descriptor that must be preserved for this
    /// listener to keep working after forking.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The provided file descriptor is not a socket.
    /// - An error occurs while creating the underlying `SocketListener`.
    pub fn new_socket_from_fd(
        socket_fd: RawDescriptor,
        keep_rds: Option<&mut Vec<RawDescriptor>>,
    ) -> anyhow::Result<Self> {
        let path = PathBuf::from(format!("/proc/self/fd/{}", socket_fd));
        if !path_is_socket(&path) {
            return Err(SocketFromFdError(path).into());
        }

        let safe_fd = safe_descriptor_from_cmdline_fd(&socket_fd)?;

        if let Some(rds) = keep_rds {
            rds.push(safe_fd.as_raw_descriptor());
        }

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

async fn stream_run_with_handler(
    stream: UnixStream,
    handler: Box<dyn vmm_vhost::Backend>,
    ex: &Executor,
) -> anyhow::Result<()> {
    let req_handler = BackendServer::new(Connection::from(stream), handler);
    run_handler(req_handler, ex).await
}

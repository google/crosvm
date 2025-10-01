// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod listener;
mod stream;

use std::future::Future;
use std::pin::Pin;

use anyhow::bail;
use anyhow::Result;
use base::warn;
use base::AsRawDescriptor;
use base::RawDescriptor;
use cros_async::Executor;
pub use listener::VhostUserListener;
pub use stream::VhostUserStream;

use crate::virtio::vhost_user_backend::BackendConnection;
use crate::virtio::vhost_user_backend::VhostUserConnectionTrait;
use crate::virtio::vhost_user_backend::VhostUserDevice;
use crate::virtio::vhost_user_backend::VhostUserDeviceBuilder;

impl BackendConnection {
    pub fn from_opts(
        socket: Option<&str>,
        socket_path: Option<&str>,
        fd: Option<RawDescriptor>,
    ) -> Result<BackendConnection> {
        let socket_path = if let Some(socket_path) = socket_path {
            Some(socket_path)
        } else if let Some(socket) = socket {
            warn!("--socket is deprecated; please use --socket-path instead");
            Some(socket)
        } else {
            None
        };

        match (socket_path, fd) {
            (Some(socket), None) => {
                let listener = VhostUserListener::new(socket)?;
                Ok(BackendConnection::Listener(listener))
            }
            (None, Some(fd)) => {
                let stream = VhostUserStream::new_socket_from_fd(fd)?;
                Ok(BackendConnection::Stream(stream))
            }
            (Some(_), Some(_)) => bail!("Cannot specify both a socket path and a file descriptor"),
            (None, None) => bail!("Must specify either a socket or a file descriptor"),
        }
    }

    pub fn run_device(
        self,
        ex: Executor,
        device: Box<dyn VhostUserDeviceBuilder>,
    ) -> anyhow::Result<()> {
        match self {
            BackendConnection::Listener(listener) => listener.run_device(ex, device),
            BackendConnection::Stream(stream) => stream.run_device(ex, device),
        }
    }

    pub fn run_backend<'e>(
        self,
        backend: impl VhostUserDevice + 'static,
        ex: &'e Executor,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'e>> {
        match self {
            BackendConnection::Listener(listener) => listener.run_backend(backend, ex),
            BackendConnection::Stream(stream) => stream.run_backend(backend, ex),
        }
    }
}

impl AsRawDescriptor for BackendConnection {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        match self {
            BackendConnection::Listener(listener) => listener.as_raw_descriptor(),
            BackendConnection::Stream(stream) => stream.as_raw_descriptor(),
        }
    }
}

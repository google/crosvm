// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use anyhow::Result;
use base::info;
use base::AsRawDescriptor;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vmm_vhost::Error as VhostError;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandler;

/// Performs the run loop for an already-constructor request handler.
pub async fn run_handler<S>(mut req_handler: SlaveReqHandler<S>, ex: &Executor) -> Result<()>
where
    S: VhostUserSlaveReqHandler,
{
    let h = SafeDescriptor::try_from(&req_handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .context("failed to get safe descriptor for handler")?;
    let handler_source = ex
        .async_from(h)
        .context("failed to create an async source")?;

    loop {
        handler_source
            .wait_readable()
            .await
            .context("failed to wait for the handler to become readable")?;
        let (hdr, files) = match req_handler.recv_header() {
            Ok((hdr, files)) => (hdr, files),
            Err(VhostError::ClientExit) => {
                info!("vhost-user connection closed");
                // Exit as the client closed the connection.
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        if req_handler.needs_wait_for_payload(&hdr) {
            handler_source
                .wait_readable()
                .await
                .context("failed to wait for the handler to become readable")?;
        }
        req_handler.process_message(hdr, files)?;
    }
}

#[cfg(test)]
pub mod test_helpers {
    use std::os::unix::net::UnixStream;

    use tempfile::TempDir;
    use vmm_vhost::connection::socket::SocketListener;
    use vmm_vhost::connection::Listener;
    use vmm_vhost::SlaveReqHandler;
    use vmm_vhost::VhostUserSlaveReqHandler;

    pub(crate) fn setup() -> (SocketListener, TempDir) {
        let dir = tempfile::Builder::new()
            .prefix("/tmp/vhost_test")
            .tempdir()
            .unwrap();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = SocketListener::new(&path, true).unwrap();

        (listener, dir)
    }

    pub(crate) fn connect(dir: tempfile::TempDir) -> UnixStream {
        let mut path = dir.path().to_owned();
        path.push("sock");
        UnixStream::connect(path).unwrap()
    }

    pub(crate) fn listen<S: VhostUserSlaveReqHandler>(
        mut listener: SocketListener,
        handler: S,
    ) -> SlaveReqHandler<S> {
        let endpoint = listener.accept().unwrap().unwrap();
        SlaveReqHandler::new(endpoint, handler)
    }
}

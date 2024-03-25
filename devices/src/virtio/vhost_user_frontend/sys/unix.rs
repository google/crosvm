// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::pin::pin;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::AsRawDescriptor;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use futures::channel::oneshot;
use futures::future::FutureExt;
use vmm_vhost::Error as VhostError;
use vmm_vhost::FrontendServer;

use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandlerImpl;
use crate::virtio::vhost_user_frontend::Error;
use crate::virtio::vhost_user_frontend::Result as VhostResult;

pub fn create_backend_req_handler(
    h: BackendReqHandlerImpl,
) -> VhostResult<(BackendReqHandler, SafeDescriptor)> {
    FrontendServer::with_stream(h).map_err(Error::CreateBackendReqHandler)
}

/// Process requests from the backend.
///
/// If `stop_rx` is sent a value, the function will exit at a well defined point so that
/// `run_backend_request_handler` can be re-invoked to resume processing the connection.
pub async fn run_backend_request_handler(
    ex: &Executor,
    handler: &mut BackendReqHandler,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let h = SafeDescriptor::try_from(handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .context("failed to get safe descriptor for handler")?;
    let handler_source = ex
        .async_from(h)
        .context("failed to create an async source")?;

    let mut wait_readable_future = pin!(handler_source.wait_readable().fuse());

    loop {
        futures::select_biased! {
            _ = stop_rx => return Ok(()),
            r = wait_readable_future => {
                r.context("failed to wait for the handler to become readable")?;
                match handler.handle_request() {
                    Ok(_) => (),
                    Err(VhostError::ClientExit) => {
                        info!("vhost-user connection closed");
                        // Exit as the client closed the connection.
                        return Ok(());
                    }
                    Err(e) => {
                        bail!("failed to handle a vhost-user request: {}", e);
                    }
                };
                wait_readable_future.set(handler_source.wait_readable().fuse());
            }
        };
    }
}

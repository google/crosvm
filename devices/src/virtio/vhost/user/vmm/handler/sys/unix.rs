// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::Mutex;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::AsRawDescriptor;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vmm_vhost::connection::socket::Endpoint as SocketEndpoint;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Master;
use vmm_vhost::MasterReqHandler;

use crate::virtio::vhost::user::vmm::handler::BackendReqHandler;
use crate::virtio::vhost::user::vmm::handler::BackendReqHandlerImpl;
use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result as VhostResult;

pub(in crate::virtio::vhost::user::vmm::handler) type SocketMaster =
    Master<SocketEndpoint<MasterReq>>;

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance attached to the provided
    /// connection with features and protocol features initialized.
    pub fn new_from_connection(
        connection: Connection,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> VhostResult<Self> {
        Self::new(
            SocketMaster::from_stream(connection),
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }
}

pub fn create_backend_req_handler(h: BackendReqHandlerImpl) -> VhostResult<BackendReqHandler> {
    let handler = MasterReqHandler::with_stream(Arc::new(Mutex::new(h)))
        .map_err(Error::CreateBackendReqHandler)?;
    Ok(handler)
}

pub async fn run_backend_request_handler(
    handler: Option<BackendReqHandler>,
    ex: &Executor,
) -> Result<()> {
    let mut handler = match handler {
        Some(h) => h,
        None => std::future::pending().await,
    };

    let h = SafeDescriptor::try_from(&handler as &dyn AsRawDescriptor)
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
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::info;
use base::AsRawDescriptor;
use base::Descriptor;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vmm_vhost::connection::socket::Endpoint as SocketEndpoint;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Master;
use vmm_vhost::MasterReqHandler;
use vmm_vhost::VhostUserMaster;

use crate::virtio::vhost::user::vmm::handler::BackendReqHandlerImpl;
use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result as VhostResult;

pub(in crate::virtio::vhost::user::vmm::handler) type SocketMaster =
    Master<SocketEndpoint<MasterReq>>;

pub(in crate::virtio::vhost::user::vmm::handler) type BackendReqHandler =
    MasterReqHandler<Mutex<BackendReqHandlerImpl>>;

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance attached to the provided UDS path
    /// with features and protocol features initialized.
    pub fn new_from_path<P: AsRef<Path>>(
        path: P,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> VhostResult<Self> {
        Self::new(
            SocketMaster::connect(path, max_queue_num)
                .map_err(Error::SocketConnectOnMasterCreate)?,
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }

    /// Creates a `VhostUserHandler` instance attached to the provided
    /// UnixSeqpacket with features and protocol features initialized.
    pub fn new_from_stream(
        sock: UnixStream,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> VhostResult<Self> {
        Self::new(
            SocketMaster::from_stream(sock, max_queue_num),
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }

    pub fn initialize_backend_req_handler(&mut self, h: BackendReqHandlerImpl) -> VhostResult<()> {
        let handler = MasterReqHandler::new(Arc::new(Mutex::new(h)))
            .map_err(Error::CreateShmemMapperError)?;
        self.vu
            .set_slave_request_fd(&Descriptor(handler.get_tx_raw_fd()))
            .map_err(Error::SetDeviceRequestChannel)?;
        self.backend_req_handler = Some(handler);
        Ok(())
    }
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

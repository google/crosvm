// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Mutex;

use base::Tube;
use cros_async::Executor;
use vmm_vhost::connection::TubeEndpoint;
use vmm_vhost::message::{MasterReq, VhostUserProtocolFeatures};
use vmm_vhost::{Error as VhostError, Master, VhostUserMasterReqHandler};

use crate::virtio::vhost::user::vmm::handler::{BackendReqHandlerImpl, VhostUserHandler};
use crate::virtio::vhost::user::vmm::{Error, Result};

// TODO(rizhang): upstream CL so SocketMaster is renamed to EndpointMaster to make it more cross
// platform.
pub(in crate::virtio::vhost::user::vmm::handler) type SocketMaster =
    Master<TubeEndpoint<MasterReq>>;

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance attached to the provided Tube
    /// with features and protocol features initialized.
    pub fn new_from_tube(
        tube: Tube,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<Self> {
        Self::new(
            SocketMaster::from_stream(tube, max_queue_num),
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }

    pub fn initialize_backend_req_handler(&mut self, h: BackendReqHandlerImpl) -> Result<()> {
        Err(Error::CreateShmemMapperError(
            VhostError::MasterInternalError,
        ))
    }
}

pub struct BackendReqHandler {}

impl VhostUserMasterReqHandler for BackendReqHandler {}

pub async fn run_backend_request_handler(
    handler: Option<BackendReqHandler>,
    _ex: &Executor,
) -> Result<()> {
    match handler {
        // We never initialize a BackendReqHandler in |initialize_backend_req_handler|.
        Some(_) => unimplemented!("unexpected BackendReqHandler"),
        None => std::future::pending().await,
    }
}

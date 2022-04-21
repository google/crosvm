// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::net::UnixStream;
use std::path::Path;

use vmm_vhost::connection::socket::Endpoint as SocketEndpoint;
use vmm_vhost::message::{MasterReq, VhostUserProtocolFeatures};
use vmm_vhost::Master;

use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::{Error, Result};

pub(in crate::virtio::vhost::user::vmm::handler) type SocketMaster =
    Master<SocketEndpoint<MasterReq>>;

impl VhostUserHandler {
    /// Creates a `VhostUserHandler` instance attached to the provided UDS path
    /// with features and protocol features initialized.
    pub fn new_from_path<P: AsRef<Path>>(
        path: P,
        max_queue_num: u64,
        allow_features: u64,
        init_features: u64,
        allow_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<Self> {
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
    ) -> Result<Self> {
        Self::new(
            SocketMaster::from_stream(sock, max_queue_num),
            allow_features,
            init_features,
            allow_protocol_features,
        )
    }
}

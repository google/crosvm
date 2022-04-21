// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Tube;
use vmm_vhost::connection::TubeEndpoint;
use vmm_vhost::message::{MasterReq, VhostUserProtocolFeatures};
use vmm_vhost::Master;

use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::Result;

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
}

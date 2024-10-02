// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::SafeDescriptor;
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

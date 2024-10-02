// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::SafeDescriptor;
use base::Tube;

use crate::virtio::vhost_user_frontend::handler::BackendReqHandler;
use crate::virtio::vhost_user_frontend::handler::BackendReqHandlerImpl;
use crate::virtio::vhost_user_frontend::Error;
use crate::virtio::vhost_user_frontend::Result as VhostResult;

pub fn create_backend_req_handler(
    h: BackendReqHandlerImpl,
    backend_pid: Option<u32>,
) -> VhostResult<(BackendReqHandler, SafeDescriptor)> {
    let backend_pid = backend_pid.expect("tube needs target pid for backend requests");
    vmm_vhost::FrontendServer::with_tube(h, backend_pid).map_err(Error::CreateBackendReqHandler)
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows specific code that keeps rest of the code in the crate platform independent.

use base::AsRawDescriptor;
use base::CloseNotifier;
use base::ReadNotifier;
use tube_transporter::packed_tube;

use crate::master_req_handler::MasterReqHandler;
use crate::Result;
use crate::VhostUserMasterReqHandler;

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a `MasterReqHandler` that uses a Tube internally. Must specify the backend process
    /// which will receive the Tube.
    pub fn with_tube(backend: S, backend_pid: u32) -> Result<Self> {
        Self::new(
            backend,
            Box::new(move |tube|
                // SAFETY:
                // Safe because we expect the tube to be unpacked in the other process.
                unsafe {
                packed_tube::pack(tube, backend_pid).expect("packed tube")
            }),
        )
    }
}

impl<S: VhostUserMasterReqHandler> ReadNotifier for MasterReqHandler<S> {
    /// Used for polling.
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.0.get_tube().get_read_notifier()
    }
}

impl<S: VhostUserMasterReqHandler> CloseNotifier for MasterReqHandler<S> {
    /// Used for closing.
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self.sub_sock.0.get_tube().get_close_notifier()
    }
}

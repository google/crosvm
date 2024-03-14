// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

use std::os::unix::io::IntoRawFd;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
use base::SafeDescriptor;

use crate::master_req_handler::MasterReqHandler;
use crate::Result;
use crate::VhostUserMasterReqHandler;

impl<S: VhostUserMasterReqHandler> AsRawDescriptor for MasterReqHandler<S> {
    /// Used for polling.
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.sub_sock.as_raw_descriptor()
    }
}

impl<S: VhostUserMasterReqHandler> MasterReqHandler<S> {
    /// Create a `MasterReqHandler` that uses a Unix stream internally.
    pub fn with_stream(backend: S) -> Result<Self> {
        Self::new(
            backend,
            Box::new(|stream|
                // SAFETY:
                // Safe because we own the raw fd.
                unsafe {
                    SafeDescriptor::from_raw_descriptor(stream.into_raw_fd())
            }),
        )
    }
}

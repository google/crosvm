// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

use std::io::Result;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

/// Alias to enable platform independent code.
pub type SystemListener = UnixListener;

/// Alias to enable platform independent code.
pub type SystemStream = UnixStream;

cfg_if::cfg_if! {
    if #[cfg(feature = "device")] {
        use crate::{connection::socket::Endpoint as SocketEndpoint};
        use crate::message::{MasterReq, SlaveReq};

        pub(crate) type SlaveReqEndpoint = SocketEndpoint<SlaveReq>;
        pub(crate) type MasterReqEndpoint = SocketEndpoint<MasterReq>;
    }
}

/// Collection of platform-specific methods that  SystemListener  provides.
pub(crate) trait SystemListenerExt {
    /// Accept a connection.
    fn accept(&self) -> Result<SystemStream>;
}

impl SystemListenerExt for SystemListener {
    fn accept(&self) -> Result<SystemStream> {
        self.accept().map(|(socket, _address)| socket)
    }
}

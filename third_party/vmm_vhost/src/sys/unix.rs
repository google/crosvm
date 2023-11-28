// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Unix specific code that keeps rest of the code in the crate platform independent.

use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

/// Alias to enable platform independent code.
pub type SystemListener = UnixListener;

/// Alias to enable platform independent code.
pub type SystemStream = UnixStream;

pub(crate) use crate::connection::socket::SocketPlatformConnection as PlatformConnection;

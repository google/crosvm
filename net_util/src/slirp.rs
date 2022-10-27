// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Contains the Rust implementation of the libslirp consumer main loop, high
//! level interfaces to libslirp that are used to implement that loop, and
//! diagnostic tools.

#![cfg(windows)]

#[path = "../../third_party/libslirp-rs/src/context.rs"]
pub mod context;

#[cfg(feature = "slirp-ring-capture")]
pub mod packet_ring_buffer;

pub mod sys;
use base::Error as SysError;
use remain::sorted;
pub use sys::Slirp;
use thiserror::Error as ThisError;

/// Length includes space for an ethernet frame & the vnet header. See the virtio spec for details:
/// <http://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006>
pub const ETHERNET_FRAME_SIZE: usize = 1526;

#[cfg(windows)]
#[sorted]
#[derive(ThisError, Debug)]
pub enum SlirpError {
    #[error("pipe was closed: {0}")]
    BrokenPipe(std::io::Error),
    #[error("failed to clone object: {0}")]
    CloneFailed(std::io::Error),
    #[error("overlapped operation failed: {0}")]
    OverlappedError(std::io::Error),
    /// Error encountered while in a Slirp related poll operation.
    #[error("slirp poll failed: {0}")]
    SlirpIOPollError(std::io::Error),
    /// Error encountered while in a Slirp related poll operation.
    #[error("slirp poll failed: {0}")]
    SlirpPollError(SysError),
    #[error("WSAStartup failed with code: {0}")]
    WSAStartupError(SysError),
}

#[cfg(windows)]
impl SlirpError {
    pub fn sys_error(&self) -> SysError {
        match &*self {
            SlirpError::BrokenPipe(e) => SysError::new(e.raw_os_error().unwrap_or_default()),
            SlirpError::CloneFailed(e) => SysError::new(e.raw_os_error().unwrap_or_default()),
            SlirpError::OverlappedError(e) => SysError::new(e.raw_os_error().unwrap_or_default()),
            SlirpError::SlirpIOPollError(e) => SysError::new(e.raw_os_error().unwrap_or_default()),
            SlirpError::SlirpPollError(e) => *e,
            SlirpError::WSAStartupError(e) => *e,
        }
    }
}

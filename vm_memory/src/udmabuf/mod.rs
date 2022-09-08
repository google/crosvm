// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod sys;

use std::io::Error as IoError;

use base::SafeDescriptor;
use remain::sorted;
pub use sys::UdmabufDriver;
use thiserror::Error;

use crate::GuestAddress;
use crate::GuestMemory;
use crate::GuestMemoryError;

#[sorted]
#[derive(Error, Debug)]
pub enum UdmabufError {
    #[error("failed to create buffer: {0:?}")]
    DmabufCreationFail(IoError),
    #[error("failed to open udmabuf driver: {0:?}")]
    DriverOpenFailed(IoError),
    #[error("failed to get region offset: {0:?}")]
    InvalidOffset(GuestMemoryError),
    #[error("All guest addresses must aligned to 4KiB")]
    NotPageAligned,
    #[error("udmabuf is not supported on this platform")]
    UdmabufUnsupported,
}

/// The result of an operation in this file.
pub type UdmabufResult<T> = std::result::Result<T, UdmabufError>;

/// Trait that the platform-specific type `UdmabufDriver` needs to implement.
pub trait UdmabufDriverTrait {
    /// Opens the udmabuf device on success.
    fn new() -> UdmabufResult<Self>
    where
        Self: Sized;

    /// Creates a dma-buf fd for the given scatter-gather list of guest memory pages (`iovecs`).
    fn create_udmabuf(
        &self,
        mem: &GuestMemory,
        iovecs: &[(GuestAddress, usize)],
    ) -> UdmabufResult<SafeDescriptor>;
}

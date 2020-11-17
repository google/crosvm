// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::FromBytesWithNulError;
use std::io;

use thiserror::Error as ThisError;

pub mod filesystem;
#[cfg(fuzzing)]
pub mod fuzzing;
pub mod mount;
mod server;
#[allow(dead_code)]
pub mod sys;
pub mod worker;

pub use mount::mount;
pub use server::{Mapper, Reader, Server, Writer};

/// Errors that may occur during the creation or operation of an Fs device.
#[derive(ThisError, Debug)]
pub enum Error {
    /// A request is missing readable descriptors.
    /// Failed to decode protocol messages.
    #[error("failed to decode fuse message: {0}")]
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    #[error("failed to encode fuse message: {0}")]
    EncodeMessage(io::Error),
    /// Failed to flush protocol messages.
    #[error("failed to flush fuse message: {0}")]
    FlushMessage(io::Error),
    /// Failed to set up FUSE endpoint to talk with.
    #[error("failed to set up FUSE endpoint to talk with: {0}")]
    EndpointSetup(io::Error),
    /// One or more parameters are missing.
    #[error("one or more parameters are missing")]
    MissingParameter,
    /// A C string parameter is invalid.
    #[error("a c string parameter is invalid: {0}")]
    InvalidCString(FromBytesWithNulError),
    /// The `len` field of the header is too small.
    #[error("the `len` field of the header is too small")]
    InvalidHeaderLength,
    /// The `size` field of the `SetxattrIn` message does not match the length
    /// of the decoded value.
    #[error(
        "The `size` field of the `SetxattrIn` message does not match the\
             length of the decoded value: size = {0}, value.len() = {1}"
    )]
    InvalidXattrSize(u32, usize),
    /// Requested too many `iovec`s for an `ioctl` retry.
    #[error(
        "requested too many `iovec`s for an `ioctl` retry reply: requested\
            {0}, max: {1}"
    )]
    TooManyIovecs(usize, usize),
}

pub type Result<T> = ::std::result::Result<T, Error>;

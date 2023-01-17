// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! FUSE (Filesystem in Userspace) server and filesystem mounting support.

#![cfg(unix)]

use std::ffi::FromBytesWithNulError;
use std::fs::File;
use std::io;

use remain::sorted;
use thiserror::Error as ThisError;

pub mod filesystem;
pub mod fuzzing;
pub mod mount;
mod server;
#[allow(dead_code)]
pub mod sys;
pub mod worker;

use filesystem::FileSystem;
pub use mount::mount;
pub use server::Mapper;
pub use server::Reader;
pub use server::Server;
pub use server::Writer;

/// Errors that may occur during the creation or operation of an Fs device.
#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// A request is missing readable descriptors.
    /// Failed to decode protocol messages.
    #[error("failed to decode fuse message: {0}")]
    DecodeMessage(io::Error),
    /// Failed to encode protocol messages.
    #[error("failed to encode fuse message: {0}")]
    EncodeMessage(io::Error),
    /// Failed to set up FUSE endpoint to talk with.
    #[error("failed to set up FUSE endpoint to talk with: {0}")]
    EndpointSetup(io::Error),
    /// Failed to flush protocol messages.
    #[error("failed to flush fuse message: {0}")]
    FlushMessage(io::Error),
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
    /// One or more parameters are missing.
    #[error("one or more parameters are missing")]
    MissingParameter,
    /// Thread exited
    #[error("Thread exited")]
    ThreadExited,
    /// Requested too many `iovec`s for an `ioctl` retry.
    #[error(
        "requested too many `iovec`s for an `ioctl` retry reply: requested\
            {0}, max: {1}"
    )]
    TooManyIovecs(usize, usize),
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Default)]
pub struct FuseConfig {
    dev_fuse_file: Option<File>,
    max_write_bytes: Option<u32>,
    max_read_bytes: Option<u32>,
    num_of_threads: Option<usize>,
}

impl FuseConfig {
    pub fn new() -> Self {
        FuseConfig {
            ..Default::default()
        }
    }

    /// Set the FUSE device.
    pub fn dev_fuse(&mut self, file: File) -> &mut Self {
        self.dev_fuse_file = Some(file);
        self
    }

    /// Set the maximum data in a read request. Must be large enough (usually equal) to `n` in
    /// `MountOption::MaxRead(n)`.
    pub fn max_read(&mut self, bytes: u32) -> &mut Self {
        self.max_read_bytes = Some(bytes);
        self
    }

    /// Set the maximum data in a write request.
    pub fn max_write(&mut self, bytes: u32) -> &mut Self {
        self.max_write_bytes = Some(bytes);
        self
    }

    /// Set the number of threads to run the `FileSystem`.
    pub fn num_threads(&mut self, num: usize) -> &mut Self {
        self.num_of_threads = Some(num);
        self
    }

    pub fn enter_message_loop<F: FileSystem + Sync + Send>(self, fs: F) -> Result<()> {
        let FuseConfig {
            dev_fuse_file,
            max_write_bytes,
            max_read_bytes,
            num_of_threads,
        } = self;
        let num = num_of_threads.unwrap_or(1);
        if num == 1 {
            worker::start_message_loop(
                dev_fuse_file.ok_or(Error::MissingParameter)?,
                max_read_bytes.ok_or(Error::MissingParameter)?,
                max_write_bytes.ok_or(Error::MissingParameter)?,
                fs,
            )
        } else {
            worker::internal::start_message_loop_mt(
                dev_fuse_file.ok_or(Error::MissingParameter)?,
                max_read_bytes.ok_or(Error::MissingParameter)?,
                max_write_bytes.ok_or(Error::MissingParameter)?,
                num,
                fs,
            )
        }
    }
}

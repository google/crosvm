// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::ops::Deref;
use std::ops::DerefMut;

use base::AsRawDescriptor;
use base::RawDescriptor;
#[cfg(unix)]
use base::UnixSeqpacket;
use remain::sorted;
use thiserror::Error as ThisError;

#[cfg(unix)]
#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// An error with EventAsync.
    #[error("An error with an EventAsync: {0}")]
    EventAsync(base::Error),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    /// An error with a polled(FD) source.
    #[error("An error with a poll source: {0}")]
    Poll(crate::sys::unix::poll_source::Error),
    /// An error with a uring source.
    #[error("An error with a uring source: {0}")]
    Uring(crate::sys::unix::uring_executor::Error),
}

#[cfg(windows)]
#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("An error with an EventAsync: {0}")]
    EventAsync(base::Error),
    #[error("An error with a handle executor: {0}")]
    HandleExecutor(crate::sys::windows::handle_executor::Error),
    #[error("An error with a handle source: {0}")]
    HandleSource(crate::sys::windows::handle_source::Error),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    #[error("An error with a handle source: {0}")]
    OverlappedSource(crate::sys::windows::overlapped_source::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(unix)]
impl From<crate::sys::unix::uring_executor::Error> for Error {
    fn from(err: crate::sys::unix::uring_executor::Error) -> Self {
        Error::Uring(err)
    }
}

#[cfg(unix)]
impl From<crate::sys::unix::poll_source::Error> for Error {
    fn from(err: crate::sys::unix::poll_source::Error) -> Self {
        Error::Poll(err)
    }
}

#[cfg(unix)]
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            Io(e) => e,
            Poll(e) => e.into(),
            Uring(e) => e.into(),
        }
    }
}

#[cfg(windows)]
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            HandleExecutor(e) => e.into(),
            HandleSource(e) => e.into(),
            Io(e) => e,
            OverlappedSource(e) => e.into(),
        }
    }
}

#[cfg(windows)]
impl From<crate::sys::windows::handle_source::Error> for Error {
    fn from(err: crate::sys::windows::handle_source::Error) -> Self {
        Error::HandleSource(err)
    }
}

#[cfg(windows)]
impl From<crate::sys::windows::handle_executor::Error> for Error {
    fn from(err: crate::sys::windows::handle_executor::Error) -> Self {
        Error::HandleExecutor(err)
    }
}

/// Marker trait signifying that the implementor is suitable for use with
/// cros_async. Examples of this include File, and base::net::UnixSeqpacket.
///
/// (Note: it'd be really nice to implement a TryFrom for any implementors, and
/// remove our factory functions. Unfortunately
/// <https://github.com/rust-lang/rust/issues/50133> makes that too painful.)
pub trait IntoAsync: AsRawDescriptor {}

impl IntoAsync for File {}
#[cfg(unix)]
impl IntoAsync for UnixSeqpacket {}

/// Simple wrapper struct to implement IntoAsync on foreign types.
pub struct AsyncWrapper<T>(T);

impl<T> AsyncWrapper<T> {
    /// Create a new `AsyncWrapper` that wraps `val`.
    pub fn new(val: T) -> Self {
        AsyncWrapper(val)
    }

    /// Consumes the `AsyncWrapper`, returning the inner struct.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for AsyncWrapper<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for AsyncWrapper<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsRawDescriptor> AsRawDescriptor for AsyncWrapper<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl<T: AsRawDescriptor> IntoAsync for AsyncWrapper<T> {}

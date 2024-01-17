// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io;
use std::ops::Deref;
use std::ops::DerefMut;

use base::AsRawDescriptor;
use base::RawDescriptor;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::UnixSeqpacket;

use crate::sys::platform::AsyncErrorSys;

#[remain::sorted]
#[derive(Debug, thiserror::Error)]
pub enum AsyncError {
    #[error("An error with an EventAsync: {0}")]
    EventAsync(base::Error),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    #[error("Platform-specific error: {0}")]
    SysVariants(#[from] AsyncErrorSys),
}

pub type AsyncResult<T> = std::result::Result<T, AsyncError>;

impl From<AsyncError> for io::Error {
    fn from(e: AsyncError) -> Self {
        match e {
            AsyncError::EventAsync(e) => e.into(),
            AsyncError::Io(e) => e,
            AsyncError::SysVariants(e) => e.into(),
        }
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
#[cfg(any(target_os = "android", target_os = "linux"))]
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

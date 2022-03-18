// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{Executor, IntoAsync};
use base::{AsRawDescriptor, RecvTube, SendTube, Tube, TubeResult};
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg_attr(windows, path = "win/async_types.rs")]
#[cfg_attr(not(windows), path = "unix/async_types.rs")]
mod async_types;
pub use async_types::*;

/// Like `cros_async::IntoAsync`, except for use with crosvm's AsRawDescriptor
/// trait object family.
pub trait DescriptorIntoAsync: AsRawDescriptor {}

/// To use an IO struct with cros_async, the type must be marked with
/// DescriptorIntoAsync (to signify it is suitable for use with async
/// operations), and then wrapped with this type.
pub struct DescriptorAdapter<T: DescriptorIntoAsync>(pub T);
impl<T> AsRawFd for DescriptorAdapter<T>
where
    T: DescriptorIntoAsync,
{
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_descriptor()
    }
}
impl<T> IntoAsync for DescriptorAdapter<T> where T: DescriptorIntoAsync {}

impl IntoAsync for Tube {}
impl IntoAsync for SendTube {}
impl IntoAsync for RecvTube {}

pub struct RecvTubeAsync(AsyncTube);
#[allow(dead_code)]
impl RecvTubeAsync {
    pub fn new(tube: RecvTube, ex: &Executor) -> io::Result<Self> {
        Ok(Self(AsyncTube::new(
            ex,
            #[allow(deprecated)]
            tube.into_tube(),
        )?))
    }

    /// TODO(b/145998747, b/184398671): this async approach needs to be refactored
    /// upstream, but for now is implemented to work using simple blocking futures
    /// (avoiding the unimplemented wait_readable).
    pub async fn next<T: 'static + DeserializeOwned + Send>(&self) -> TubeResult<T> {
        self.0.next().await
    }
}

pub struct SendTubeAsync(AsyncTube);
#[allow(dead_code)]
impl SendTubeAsync {
    pub fn new(tube: SendTube, ex: &Executor) -> io::Result<Self> {
        Ok(Self(AsyncTube::new(
            ex,
            #[allow(deprecated)]
            tube.into_tube(),
        )?))
    }

    pub async fn send<T: 'static + Serialize + Send + Sync>(&self, msg: T) -> TubeResult<()> {
        self.0.send(msg).await
    }
}

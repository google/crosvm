// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{Executor, IntoAsync, IoSourceExt};
use base::{AsRawDescriptor, Tube, TubeResult};
use serde::de::DeserializeOwned;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, RawFd};

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

pub struct AsyncTube {
    inner: Box<dyn IoSourceExt<Tube>>,
}

impl AsyncTube {
    pub fn new(ex: &Executor, tube: Tube) -> std::io::Result<AsyncTube> {
        return Ok(AsyncTube {
            inner: ex.async_from(tube)?,
        });
    }

    pub async fn next<T: DeserializeOwned>(&self) -> TubeResult<T> {
        self.inner.wait_readable().await.unwrap();
        self.inner.as_source().recv()
    }
}

impl Deref for AsyncTube {
    type Target = Tube;

    fn deref(&self) -> &Self::Target {
        self.inner.as_source()
    }
}

impl From<AsyncTube> for Tube {
    fn from(at: AsyncTube) -> Tube {
        at.inner.into_source()
    }
}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use base::RecvTube;
use base::SendTube;
use base::Tube;
use base::TubeResult;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub use crate::sys::async_types::*;
use crate::Executor;
use crate::IntoAsync;

// NOTE: A StreamChannel can either be used fully in async mode, or not in async
// mode. Mixing modes will break StreamChannel's internal read/write
// notification system.
//
// TODO(b/213153157): this type isn't properly available upstream yet. Once it
// is, we can re-enable these implementations.
// impl IntoAsync for StreamChannel {}
// impl IntoAsync for &StreamChannel {}

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

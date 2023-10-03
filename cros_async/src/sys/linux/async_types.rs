// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::ops::Deref;

use base::Tube;
use base::TubeResult;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::Executor;
use crate::IoSource;

pub struct AsyncTube {
    inner: IoSource<Tube>,
}

impl AsyncTube {
    pub fn new(ex: &Executor, tube: Tube) -> io::Result<AsyncTube> {
        Ok(AsyncTube {
            inner: ex.async_from(tube)?,
        })
    }

    pub async fn next<T: DeserializeOwned>(&self) -> TubeResult<T> {
        self.inner.wait_readable().await.unwrap();
        self.inner.as_source().recv()
    }

    pub async fn send<T: 'static + Serialize + Send + Sync>(&self, msg: T) -> TubeResult<()> {
        self.inner.as_source().send(&msg)
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

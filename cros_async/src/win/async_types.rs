// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{Executor, HandleWrapper};
use base::{AsRawDescriptor, Descriptor, RecvTube, SendTube, Tube, TubeResult};
use serde::de::DeserializeOwned;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};

pub struct AsyncTube {
    inner: Arc<Mutex<Tube>>,
}

impl AsyncTube {
    pub fn new(ex: &Executor, tube: Tube) -> io::Result<AsyncTube> {
        Ok(AsyncTube {
            inner: Arc::new(Mutex::new(tube)),
        })
    }

    /// TODO(b/145998747, b/184398671): this async approach needs to be refactored
    /// upstream, but for now is implemented to work using simple blocking futures
    /// (avoiding the unimplemented wait_readable).
    pub async fn next<T: 'static + DeserializeOwned + Send>(&self) -> TubeResult<T> {
        let tube = Arc::clone(&self.inner);
        let handles = HandleWrapper::new(vec![Descriptor(tube.lock().unwrap().as_raw_handle())]);
        unblock(
            move || tube.lock().unwrap().recv(),
            move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
        )
        .await
    }

    pub async fn send<T: 'static + Serialize + Send + Sync>(&self, msg: T) -> TubeResult<()> {
        let tube = Arc::clone(&self.inner);
        let handles = HandleWrapper::new(vec![Descriptor(tube.lock().unwrap().as_raw_handle())]);
        unblock(
            move || tube.lock().unwrap().send(&msg),
            move || Err(handles.lock().cancel_sync_io(Error::OperationCancelled)),
        )
        .await
    }
}

impl From<AsyncTube> for Tube {
    fn from(at: AsyncTube) -> Tube {
        // We ensure this is safe by waiting to acquire the mutex on
        // the tube before unwrapping. This only works because the
        // worker thread in "next" holds the mutex for its entire life.
        //
        // This does however mean that into will block until all async
        // operations are complete.
        let _ = at.inner.lock().unwrap();
        Arc::try_unwrap(at.inner).unwrap().into_inner().unwrap()
    }
}

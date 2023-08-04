// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::sync::Arc;
use std::sync::Mutex;

use base::AsRawDescriptor;
use base::Descriptor;
use base::ReadNotifier;
use base::Tube;
use base::TubeError;
use base::TubeResult;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::HandleWrapper;
use crate::unblock;
use crate::EventAsync;
use crate::Executor;

pub struct AsyncTube {
    inner: Arc<Mutex<Tube>>,
    read_notifier: EventAsync,
}

impl AsyncTube {
    pub fn new(ex: &Executor, tube: Tube) -> io::Result<AsyncTube> {
        let read_notifier = EventAsync::clone_raw_without_reset(tube.get_read_notifier(), ex)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let inner = Arc::new(Mutex::new(tube));
        Ok(AsyncTube {
            inner,
            read_notifier,
        })
    }

    /// TODO(b/145998747, b/184398671): this async approach needs to be refactored
    /// upstream, but for now is implemented to work using simple blocking futures
    /// (avoiding the unimplemented wait_readable).
    pub async fn next<T: 'static + DeserializeOwned + Send>(&self) -> TubeResult<T> {
        self.read_notifier
            .next_val()
            .await
            .map_err(|e| TubeError::Recv(io::Error::new(io::ErrorKind::Other, e)))?;
        let tube = Arc::clone(&self.inner);
        let handles =
            HandleWrapper::new(vec![Descriptor(tube.lock().unwrap().as_raw_descriptor())]);
        unblock(
            move || tube.lock().unwrap().recv(),
            move || Err(handles.lock().cancel_sync_io(TubeError::OperationCancelled)),
        )
        .await
    }

    pub async fn send<T: 'static + Serialize + Send + Sync>(&self, msg: T) -> TubeResult<()> {
        let tube = Arc::clone(&self.inner);
        let handles =
            HandleWrapper::new(vec![Descriptor(tube.lock().unwrap().as_raw_descriptor())]);
        unblock(
            move || tube.lock().unwrap().send(&msg),
            move || Err(handles.lock().cancel_sync_io(TubeError::OperationCancelled)),
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
        std::mem::drop(at.inner.lock().unwrap());
        Arc::try_unwrap(at.inner).unwrap().into_inner().unwrap()
    }
}

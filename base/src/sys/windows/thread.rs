// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::any::Any;
use std::panic;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Spawns a thread that can be joined with a timeout.
pub fn spawn_with_timeout<F, T>(f: F) -> JoinHandleWithTimeout<T>
where
    F: FnOnce() -> T,
    F: Send + 'static,
    T: Send + 'static,
{
    // Use a channel to signal completion to the join handle
    let (tx, rx) = channel();
    let handle = thread::spawn(move || {
        let val = panic::catch_unwind(panic::AssertUnwindSafe(f));
        tx.send(()).unwrap();
        val
    });
    JoinHandleWithTimeout { handle, rx }
}

pub struct JoinHandleWithTimeout<T> {
    handle: JoinHandle<thread::Result<T>>,
    rx: Receiver<()>,
}

#[derive(Debug)]
pub enum JoinError {
    Panic(Box<dyn Any>),
    Timeout,
}

impl<T> JoinHandleWithTimeout<T> {
    /// Tries to join the thread.  Returns an error if the join takes more than `timeout_ms`.
    pub fn try_join(self, timeout: Duration) -> Result<T, JoinError> {
        if self.rx.recv_timeout(timeout).is_ok() {
            self.handle.join().unwrap().map_err(|e| JoinError::Panic(e))
        } else {
            Err(JoinError::Timeout)
        }
    }
}

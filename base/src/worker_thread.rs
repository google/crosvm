// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Worker thread abstraction

use std::panic;
use std::thread;
use std::thread::JoinHandle;
use std::thread::Thread;

use crate::Error;
use crate::Event;

/// Wrapper object for creating a worker thread that can be stopped by signaling an event.
pub struct WorkerThread<T: Send + 'static> {
    worker: Option<(Event, JoinHandle<T>)>,
}

impl<T: Send + 'static> WorkerThread<T> {
    /// Starts a worker thread named `thread_name` running the `thread_func` function.
    ///
    /// The `thread_func` implementation must monitor the provided `Event` and return from the
    /// thread when it is signaled.
    ///
    /// Call [`stop()`](Self::stop) to stop the thread.
    pub fn start<F>(thread_name: impl Into<String>, thread_func: F) -> Self
    where
        F: FnOnce(Event) -> T + Send + 'static,
    {
        let stop_event = Event::new().expect("Event::new() failed");
        let thread_stop_event = stop_event.try_clone().expect("Event::try_clone() failed");

        let thread_handle = thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || thread_func(thread_stop_event))
            .expect("thread spawn failed");

        WorkerThread {
            worker: Some((stop_event, thread_handle)),
        }
    }

    /// Stops the worker thread.
    ///
    /// Returns the value returned by the function running in the thread.
    pub fn stop(mut self) -> T {
        // The only time the internal `Option` should be `None` is in a `drop` after `stop`, so this
        // `expect()` should never fail.
        self.stop_internal().expect("invalid worker state")
    }

    // `stop_internal` accepts a reference so it can be called from `drop`.
    #[doc(hidden)]
    fn stop_internal(&mut self) -> Option<T> {
        self.worker.take().map(|(stop_event, thread_handle)| {
            // There is nothing the caller can do to handle `stop_event.signal()` failure, and we
            // don't want to leave the thread running, so panic in that case.
            stop_event
                .signal()
                .expect("WorkerThread stop event signal failed");

            match thread_handle.join() {
                Ok(v) => v,
                Err(e) => panic::resume_unwind(e),
            }
        })
    }

    /// Signal thread's stop event. Unlike stop, the function doesn't wait
    /// on joining the thread.
    /// The function can be called multiple times.
    /// Calling `stop` or `drop` will internally signal the stop event again
    /// and join the thread.
    pub fn signal(&mut self) -> Result<(), Error> {
        if let Some((event, _)) = &mut self.worker {
            event.signal()
        } else {
            Ok(())
        }
    }

    /// Returns a handle to the running thread.
    pub fn thread(&self) -> &Thread {
        // The only time the internal `Option` should be `None` is in a `drop` after `stop`, so this
        // `unwrap()` should never fail.
        self.worker.as_ref().unwrap().1.thread()
    }
}

impl<T: Send + 'static> Drop for WorkerThread<T> {
    /// Stops the thread if the `WorkerThread` is dropped without calling [`stop()`](Self::stop).
    fn drop(&mut self) {
        let _ = self.stop_internal();
    }
}

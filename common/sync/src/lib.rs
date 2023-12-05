// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Sync primitive types whose methods panic rather than returning error in case of poison.
//!
//! The Mutex/Condvar type in this crates wraps the standard library versions and mirrors the same
//! methods, except that they panic where the standard library would return an Error. This API
//! codifies our error handling strategy around poisoned mutexes in crosvm.
//!
//! - Crosvm releases are built with panic=abort so poisoning never occurs. A panic while a mutex is
//!   held (or ever) takes down the entire process. Thus we would like for code not to have to
//!   consider the possibility of poison.
//!
//! - We could ask developers to always write `.lock().unwrap()` on a standard library mutex.
//!   However, we would like to stigmatize the use of unwrap. It is confusing to permit unwrap but
//!   only on mutex lock results. During code review it may not always be obvious whether a
//!   particular unwrap is unwrapping a mutex lock result or a different error that should be
//!   handled in a more principled way.
//!
//! Developers should feel free to use types defined in this crate anywhere in crosvm that they
//! would otherwise be using the corresponding types in std::sync.

mod condvar;
mod mutex;

use std::sync::Arc;
use std::sync::WaitTimeoutResult;
use std::time::Duration;

pub use crate::condvar::Condvar;
pub use crate::mutex::Mutex;
pub use crate::mutex::WouldBlock;

/// Waitable allows one thread to wait on a signal from another thread.
///
/// A Waitable is usually created with a Promise using
/// `create_promise_and_waitable`, and the Promise is used by one thread and the
/// Waitable can be used by another thread. Promise and Waitable do not use any
/// OS-level synchronization primitives.
pub struct Waitable(Arc<(Condvar, Mutex<bool>)>);

impl Waitable {
    /// Return an already-signaled Waitable.
    pub fn signaled() -> Self {
        Waitable(Arc::new((Condvar::new(), Mutex::new(true))))
    }

    /// Perform a blocking wait on this Waitable.
    pub fn wait(&self, timeout: Option<Duration>) -> WaitTimeoutResult {
        let timeout = timeout.unwrap_or(Duration::MAX);
        let (ref condvar, ref signaled_mutex) = *self.0;
        condvar
            .wait_timeout_while(signaled_mutex.lock(), timeout, |signaled| !*signaled)
            .1
    }
}

/// Promise allows one thread to signal a waitable that another thread can wait on.
pub struct Promise(Arc<(Condvar, Mutex<bool>)>);

impl Promise {
    /// Signal this promise, and it's associated Waitable.
    pub fn signal(&self) {
        let (ref condvar, ref signaled_mutex) = *self.0;
        *signaled_mutex.lock() = true;
        condvar.notify_all();
    }
}

/// Create a paired Promise and Waitable.
///
/// Signalling the Promise will signal the Waitable.
pub fn create_promise_and_waitable() -> (Promise, Waitable) {
    let inner = Arc::new((Condvar::new(), Mutex::new(false)));
    (Promise(Arc::clone(&inner)), Waitable(inner))
}

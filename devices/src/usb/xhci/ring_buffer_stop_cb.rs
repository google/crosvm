// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::utils::FailHandle;
use std::sync::{Arc, Mutex};
use sys_util::error;

/// RingBufferStopCallback wraps a callback. The callback will be invoked when last instance of
/// RingBufferStopCallback and its clones is dropped.
///
/// The callback might not be invoked in certain cases. Don't depend this for safety.
#[derive(Clone)]
pub struct RingBufferStopCallback {
    inner: Arc<Mutex<RingBufferStopCallbackInner>>,
}

impl RingBufferStopCallback {
    /// Create new callback from closure.
    pub fn new<C: 'static + FnMut() + Send>(cb: C) -> RingBufferStopCallback {
        RingBufferStopCallback {
            inner: Arc::new(Mutex::new(RingBufferStopCallbackInner {
                callback: Box::new(cb),
            })),
        }
    }
}

struct RingBufferStopCallbackInner {
    callback: Box<dyn FnMut() + Send>,
}

impl Drop for RingBufferStopCallbackInner {
    fn drop(&mut self) {
        (self.callback)();
    }
}

/// Helper function to wrap up a closure with fail handle. The fail handle will be triggered if the
/// closure returns an error.
pub fn fallible_closure<E: std::fmt::Display, C: FnMut() -> Result<(), E> + 'static + Send>(
    fail_handle: Arc<dyn FailHandle>,
    mut callback: C,
) -> impl FnMut() + 'static + Send {
    move || match callback() {
        Ok(()) => {}
        Err(e) => {
            error!("callback failed {}", e);
            fail_handle.fail();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn task(_: RingBufferStopCallback) {}

    #[test]
    fn simple_raii_callback() {
        let a = Arc::new(Mutex::new(0));
        let ac = a.clone();
        let cb = RingBufferStopCallback::new(move || {
            *ac.lock().unwrap() = 1;
        });
        task(cb.clone());
        task(cb.clone());
        task(cb);
        assert_eq!(*a.lock().unwrap(), 1);
    }
}

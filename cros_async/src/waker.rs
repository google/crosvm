// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::task::ArcWake;

/// Wrapper around a u64 used as a token to uniquely identify a pending waker.
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub(crate) struct WakerToken(pub(crate) u64);

/// Raw waker used by executors. Associated with a single future and used to indicate whether that
/// future needs to be polled.
pub(crate) struct NeedsPoll(AtomicBool);

impl NeedsPoll {
    /// Creates a new `NeedsPoll` initialized to `true`.
    pub fn new() -> Arc<NeedsPoll> {
        Arc::new(NeedsPoll(AtomicBool::new(true)))
    }

    /// Returns the current value of this `NeedsPoll`.
    pub fn get(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Changes the internal value to `val` and returns the old value.
    pub fn swap(&self, val: bool) -> bool {
        self.0.swap(val, Ordering::AcqRel)
    }
}

impl ArcWake for NeedsPoll {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.store(true, Ordering::Release);
    }
}

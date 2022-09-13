// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::VecDeque;

use async_task::Runnable;
use sync::Mutex;

/// A queue of `Runnables`. Intended to be used by executors to keep track of futures that have been
/// scheduled to run.
pub struct RunnableQueue {
    runnables: Mutex<VecDeque<Runnable>>,
}

impl RunnableQueue {
    /// Create a new, empty `RunnableQueue`.
    pub fn new() -> RunnableQueue {
        RunnableQueue {
            runnables: Mutex::new(VecDeque::new()),
        }
    }

    /// Schedule `runnable` to run in the future by adding it to this `RunnableQueue`.
    pub fn push_back(&self, runnable: Runnable) {
        self.runnables.lock().push_back(runnable);
    }

    /// Remove and return the first `Runnable` in this `RunnableQueue` or `None` if it is empty.
    pub fn pop_front(&self) -> Option<Runnable> {
        self.runnables.lock().pop_front()
    }

    /// Create an iterator over this `RunnableQueue` that repeatedly calls `pop_front()` until it is
    /// empty.
    pub fn iter(&self) -> RunnableQueueIter {
        self.into_iter()
    }
}

impl Default for RunnableQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl<'q> IntoIterator for &'q RunnableQueue {
    type Item = Runnable;
    type IntoIter = RunnableQueueIter<'q>;

    fn into_iter(self) -> Self::IntoIter {
        RunnableQueueIter { queue: self }
    }
}

/// An iterator over a `RunnableQueue`.
pub struct RunnableQueueIter<'q> {
    queue: &'q RunnableQueue,
}

impl<'q> Iterator for RunnableQueueIter<'q> {
    type Item = Runnable;
    fn next(&mut self) -> Option<Self::Item> {
        self.queue.pop_front()
    }
}

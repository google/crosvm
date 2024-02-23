// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Debug;
use std::sync::Condvar as StdCondvar;
use std::sync::MutexGuard;
use std::sync::WaitTimeoutResult;
use std::time::Duration;

static CONDVAR_POISONED: &str = "condvar is poisoned";

/// A Condition Variable.
#[derive(Default)]
pub struct Condvar {
    std: StdCondvar,
}

impl Condvar {
    /// Creates a new condvar that is ready to be waited on.
    pub const fn new() -> Condvar {
        Condvar {
            std: StdCondvar::new(),
        }
    }

    /// Waits on a condvar, blocking the current thread until it is notified.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        self.std.wait(guard).expect(CONDVAR_POISONED)
    }

    /// Blocks the current thread until this condition variable receives a notification and the
    /// provided condition is false.
    pub fn wait_while<'a, T, F>(&self, guard: MutexGuard<'a, T>, condition: F) -> MutexGuard<'a, T>
    where
        F: FnMut(&mut T) -> bool,
    {
        self.std
            .wait_while(guard, condition)
            .expect(CONDVAR_POISONED)
    }

    /// Waits on a condvar, blocking the current thread until it is notified
    /// or the specified duration has elapsed.
    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        self.std.wait_timeout(guard, dur).expect(CONDVAR_POISONED)
    }

    /// Waits on this condition variable for a notification, timing out after a specified duration.
    pub fn wait_timeout_while<'a, T, F>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: Duration,
        condition: F,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult)
    where
        F: FnMut(&mut T) -> bool,
    {
        self.std
            .wait_timeout_while(guard, dur, condition)
            .expect(CONDVAR_POISONED)
    }

    /// Notifies one thread blocked by this condvar.
    pub fn notify_one(&self) {
        self.std.notify_one();
    }

    /// Notifies all threads blocked by this condvar.
    pub fn notify_all(&self) {
        self.std.notify_all();
    }
}

impl Debug for Condvar {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.std, formatter)
    }
}

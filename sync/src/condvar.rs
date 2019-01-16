// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Debug};
use std::sync::{Condvar as StdCondvar, MutexGuard};

/// A Condition Variable.
#[derive(Default)]
pub struct Condvar {
    std: StdCondvar,
}

impl Condvar {
    /// Creates a new condvar that is ready to be waited on.
    pub fn new() -> Condvar {
        Condvar {
            std: StdCondvar::new(),
        }
    }

    /// Waits on a condvar, blocking the current thread until it is notified.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        match self.std.wait(guard) {
            Ok(guard) => guard,
            Err(_) => panic!("condvar is poisoned"),
        }
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

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Defines Windows-specific submodules of sys_util

mod platform_timer_utils;
pub use platform_timer_utils::*;

use std::ptr::null_mut;

use serde::Deserialize;
use serde::Serialize;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::synchapi::CreateMutexA;
use winapi::um::synchapi::ReleaseMutex;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winbase::WAIT_ABANDONED;
use winapi::um::winbase::WAIT_OBJECT_0;

use super::Error;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;

/// A Mutex (no data) that works across processes on Windows.
#[derive(Serialize, Deserialize, Debug)]
pub struct MultiProcessMutex {
    lock: SafeDescriptor,
}

impl MultiProcessMutex {
    pub fn new() -> Result<Self> {
        // Trivially safe (no memory passed, error checked).
        //
        // Note that we intentionally make this handle uninheritable by default via the mutex attrs.
        let lock_handle = unsafe {
            CreateMutexA(
                /* lpMutexAttributes= */ null_mut(),
                false as i32,
                null_mut(),
            )
        };

        if lock_handle == INVALID_HANDLE_VALUE {
            Err(Error::last())
        } else {
            Ok(Self {
                // Safe because the handle is valid & we own it exclusively.
                lock: unsafe { SafeDescriptor::from_raw_descriptor(lock_handle) },
            })
        }
    }

    /// Locks the mutex, returning a RAII guard similar to std::sync::Mutex.
    pub fn lock(&self) -> MultiProcessMutexGuard {
        if let Some(guard) = self.try_lock(INFINITE) {
            guard
        } else {
            // This should *never* happen.
            panic!("Timed out locking mutex with an infinite timeout. This should never happen.");
        }
    }

    /// Tries to lock the mutex, returning a RAII guard similar to std::sync::Mutex if we obtained
    /// the lock within the timeout.
    pub fn try_lock(&self, timeout_ms: u32) -> Option<MultiProcessMutexGuard> {
        // Safe because the mutex handle is guaranteed to exist.
        match unsafe { WaitForSingleObject(self.lock.as_raw_descriptor(), timeout_ms) } {
            WAIT_OBJECT_0 => Some(MultiProcessMutexGuard { lock: &self.lock }),
            WAIT_TIMEOUT => None,
            WAIT_ABANDONED => panic!(
                "The thread holding the mutex exited without releasing the mutex.\
                 Protected data may be corrupt."
            ),
            _ => {
                // This should *never* happen.
                panic!("Failed to lock mutex {:?}", Error::last())
            }
        }
    }

    /// Creates a new reference to the mutex.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            lock: self.lock.try_clone()?,
        })
    }
}

/// RAII guard for MultiProcessMutex.
pub struct MultiProcessMutexGuard<'a> {
    lock: &'a SafeDescriptor,
}

impl<'a> Drop for MultiProcessMutexGuard<'a> {
    fn drop(&mut self) {
        if unsafe { ReleaseMutex(self.lock.as_raw_descriptor()) } == 0 {
            panic!("Failed to unlock mutex: {:?}.", Error::last())
        }
    }
}

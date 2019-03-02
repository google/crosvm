// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Mutex type whose methods panic rather than returning error in case of
//! poison.
//!
//! The Mutex type in this module wraps the standard library Mutex and mirrors
//! the same methods, except that they panic where the standard library would
//! return a PoisonError. This API codifies our error handling strategy around
//! poisoned mutexes in crosvm.
//!
//! - Crosvm releases are built with panic=abort so poisoning never occurs. A
//!   panic while a mutex is held (or ever) takes down the entire process. Thus
//!   we would like for code not to have to consider the possibility of poison.
//!
//! - We could ask developers to always write `.lock().unwrap()` on a standard
//!   library mutex. However, we would like to stigmatize the use of unwrap. It
//!   is confusing to permit unwrap but only on mutex lock results. During code
//!   review it may not always be obvious whether a particular unwrap is
//!   unwrapping a mutex lock result or a different error that should be handled
//!   in a more principled way.
//!
//! Developers should feel free to use sync::Mutex anywhere in crosvm that they
//! would otherwise be using std::sync::Mutex.

use std::fmt::{self, Debug, Display};
use std::sync::{Mutex as StdMutex, MutexGuard, TryLockError};

/// A mutual exclusion primitive useful for protecting shared data.
#[derive(Default)]
pub struct Mutex<T: ?Sized> {
    std: StdMutex<T>,
}

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state ready for use.
    pub fn new(value: T) -> Mutex<T> {
        Mutex {
            std: StdMutex::new(value),
        }
    }

    /// Consumes this mutex, returning the underlying data.
    pub fn into_inner(self) -> T {
        match self.std.into_inner() {
            Ok(value) => value,
            Err(_) => panic!("mutex is poisoned"),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires a mutex, blocking the current thread until it is able to do so.
    ///
    /// This function will block the local thread until it is available to
    /// acquire the mutex. Upon returning, the thread is the only thread with
    /// the lock held. An RAII guard is returned to allow scoped unlock of the
    /// lock. When the guard goes out of scope, the mutex will be unlocked.
    pub fn lock(&self) -> MutexGuard<T> {
        match self.std.lock() {
            Ok(guard) => guard,
            Err(_) => panic!("mutex is poisoned"),
        }
    }

    /// Attempts to acquire this lock.
    ///
    /// If the lock could not be acquired at this time, then Err is returned.
    /// Otherwise, an RAII guard is returned. The lock will be unlocked when the
    /// guard is dropped.
    ///
    /// This function does not block.
    pub fn try_lock(&self) -> Result<MutexGuard<T>, WouldBlock> {
        match self.std.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::Poisoned(_)) => panic!("mutex is poisoned"),
            Err(TryLockError::WouldBlock) => Err(WouldBlock),
        }
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the Mutex mutably, no actual locking needs to
    /// take place -- the mutable borrow statically guarantees no locks exist.
    pub fn get_mut(&mut self) -> &mut T {
        match self.std.get_mut() {
            Ok(value) => value,
            Err(_) => panic!("mutex is poisoned"),
        }
    }
}

impl<T> From<T> for Mutex<T> {
    fn from(value: T) -> Self {
        Mutex {
            std: StdMutex::from(value),
        }
    }
}

impl<T: ?Sized + Debug> Debug for Mutex<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.std, formatter)
    }
}

/// The lock could not be acquired at this time because the operation would
/// otherwise block.
///
/// Error returned by Mutex::try_lock.
#[derive(Debug)]
pub struct WouldBlock;

impl Display for WouldBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&TryLockError::WouldBlock::<()>, formatter)
    }
}

impl std::error::Error for WouldBlock {}

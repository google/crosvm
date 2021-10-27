// Copyright 2018 The Chromium OS Authors. All rights reserved.
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

pub use crate::condvar::Condvar;
pub use crate::mutex::{Mutex, WouldBlock};

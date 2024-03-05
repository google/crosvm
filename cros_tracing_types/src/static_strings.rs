// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides a mechanism to turn an arbitrary CStr into a static. The primary
//! use is for FFIs like Perfetto which require any trace point names to be
//! static.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::raw::c_char;

use sync::Mutex;

static STATIC_STRINGS: Mutex<BTreeSet<CString>> = Mutex::new(BTreeSet::new());

/// Holds a reference to a 'static string that was registered via `register_string`.
#[derive(Clone, Copy)]
pub struct StaticString(*const c_char);

impl StaticString {
    #[inline]
    pub fn as_ptr(&self) -> *const c_char {
        self.0
    }

    /// Turns a given string into a *c_char which has static lifetime measured
    /// from the moment this function returns. Registering the same string
    /// multiple times behaves like interning (will not use additional
    /// resources).
    ///
    /// WARNING: this function creates data with static lifetime. It should only
    /// be called on a finite set of unique strings. Using it on a non-finite
    /// set will appear to be a memory leak since the space used will grow
    /// without bound.
    pub fn register(str: &str) -> Self {
        let c_str = CString::new(str).expect("failed to convert a tracing string to a CString.");
        let mut strings = STATIC_STRINGS.lock();
        strings.insert(c_str.clone());
        Self(strings.get(&c_str).unwrap().as_ptr())
    }
}

// Safety: pointers are safe to send between threads.
unsafe impl Send for StaticString {}
// SAFETY:
// Safe to share across threads, because `register` is protected by a lock and strings inserted
// are never removed.
unsafe impl Sync for StaticString {}

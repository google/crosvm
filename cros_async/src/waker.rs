// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{RawWaker, RawWakerVTable};

/// Wrapper around a u64 used as a token to uniquely identify a pending waker.
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub(crate) struct WakerToken(pub(crate) u64);

// Boiler-plate for creating a waker with function pointers.
// This waker sets the atomic bool it is passed to true.
// The bool will be used by the executor to know which futures to poll

// Convert the pointer back to the Rc it was created from and drop it.
unsafe fn waker_drop(data_ptr: *const ()) {
    // from_raw, then drop
    let _rc_bool = Rc::<AtomicBool>::from_raw(data_ptr as *const _);
}

unsafe fn waker_wake(data_ptr: *const ()) {
    waker_wake_by_ref(data_ptr)
}

// Called when the bool should be set to true to wake the waker.
unsafe fn waker_wake_by_ref(data_ptr: *const ()) {
    let bool_atomic_ptr = data_ptr as *const AtomicBool;
    let bool_atomic_ref = bool_atomic_ptr.as_ref().unwrap();
    bool_atomic_ref.store(true, Ordering::Relaxed);
}

// The data_ptr will be a pointer to an Rc<AtomicBool>.
unsafe fn waker_clone(data_ptr: *const ()) -> RawWaker {
    let rc_bool = Rc::<AtomicBool>::from_raw(data_ptr as *const _);
    let new_ptr = rc_bool.clone();
    Rc::into_raw(rc_bool); // Don't decrement the ref count of the original, so back to raw.
    create_waker(Rc::into_raw(new_ptr) as *const _)
}

static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

/// To use safely, data_ptr must be from Rc<AtomicBool>::from_raw().
pub unsafe fn create_waker(data_ptr: *const ()) -> RawWaker {
    RawWaker::new(data_ptr, &WAKER_VTABLE)
}

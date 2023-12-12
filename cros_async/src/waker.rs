// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::drop;
use std::mem::ManuallyDrop;
use std::sync::Weak;
use std::task::RawWaker;
use std::task::RawWakerVTable;
use std::task::Waker;

/// Wrapper around a usize used as a token to uniquely identify a pending waker.
#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
pub(crate) struct WakerToken(pub(crate) usize);

/// Like `futures::task::ArcWake` but uses `Weak<T>` instead of `Arc<T>`.
pub(crate) trait WeakWake: Send + Sync {
    fn wake_by_ref(weak_self: &Weak<Self>);

    fn wake(weak_self: Weak<Self>) {
        Self::wake_by_ref(&weak_self)
    }
}

fn waker_vtable<W: WeakWake>() -> &'static RawWakerVTable {
    &RawWakerVTable::new(
        clone_weak_raw::<W>,
        wake_weak_raw::<W>,
        wake_by_ref_weak_raw::<W>,
        drop_weak_raw::<W>,
    )
}

unsafe fn clone_weak_raw<W: WeakWake>(data: *const ()) -> RawWaker {
    // Get a handle to the Weak<T> but wrap it in a ManuallyDrop so that we don't reduce the
    // refcount at the end of this function.
    let weak = ManuallyDrop::new(Weak::<W>::from_raw(data as *const W));

    // Now increase the weak count and keep it in a ManuallyDrop so that it doesn't get decreased
    // at the end of this function.
    let _weak_clone: ManuallyDrop<_> = weak.clone();

    RawWaker::new(data, waker_vtable::<W>())
}

unsafe fn wake_weak_raw<W: WeakWake>(data: *const ()) {
    let weak: Weak<W> = Weak::from_raw(data as *const W);

    WeakWake::wake(weak)
}

unsafe fn wake_by_ref_weak_raw<W: WeakWake>(data: *const ()) {
    // Get a handle to the Weak<T> but wrap it in a ManuallyDrop so that we don't reduce the
    // refcount at the end of this function.
    let weak = ManuallyDrop::new(Weak::<W>::from_raw(data as *const W));

    WeakWake::wake_by_ref(&weak)
}

unsafe fn drop_weak_raw<W: WeakWake>(data: *const ()) {
    drop(Weak::from_raw(data as *const W))
}

pub(crate) fn new_waker<W: WeakWake>(w: Weak<W>) -> Waker {
    // TODO(b/315998194): Add safety comment
    #[allow(clippy::undocumented_unsafe_blocks)]
    unsafe {
        Waker::from_raw(RawWaker::new(
            w.into_raw() as *const (),
            waker_vtable::<W>(),
        ))
    }
}

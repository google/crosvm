// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::UnsafeCell;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use intrusive_collections::linked_list::{LinkedList, LinkedListOps};
use intrusive_collections::{intrusive_adapter, DefaultLinkOps, LinkOps};

use crate::sync::SpinLock;

// An atomic version of a LinkedListLink. See https://github.com/Amanieu/intrusive-rs/issues/47 for
// more details.
pub struct AtomicLink {
    prev: UnsafeCell<Option<NonNull<AtomicLink>>>,
    next: UnsafeCell<Option<NonNull<AtomicLink>>>,
    linked: AtomicBool,
}

impl AtomicLink {
    fn new() -> AtomicLink {
        AtomicLink {
            linked: AtomicBool::new(false),
            prev: UnsafeCell::new(None),
            next: UnsafeCell::new(None),
        }
    }

    fn is_linked(&self) -> bool {
        self.linked.load(Ordering::Relaxed)
    }
}

impl DefaultLinkOps for AtomicLink {
    type Ops = AtomicLinkOps;

    const NEW: Self::Ops = AtomicLinkOps;
}

// Safe because the only way to mutate `AtomicLink` is via the `LinkedListOps` trait whose methods
// are all unsafe and require that the caller has first called `acquire_link` (and had it return
// true) to use them safely.
unsafe impl Send for AtomicLink {}
unsafe impl Sync for AtomicLink {}

#[derive(Copy, Clone, Default)]
pub struct AtomicLinkOps;

unsafe impl LinkOps for AtomicLinkOps {
    type LinkPtr = NonNull<AtomicLink>;

    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        !ptr.as_ref().linked.swap(true, Ordering::Acquire)
    }

    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref().linked.store(false, Ordering::Release)
    }
}

unsafe impl LinkedListOps for AtomicLinkOps {
    unsafe fn next(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        *ptr.as_ref().next.get()
    }

    unsafe fn prev(&self, ptr: Self::LinkPtr) -> Option<Self::LinkPtr> {
        *ptr.as_ref().prev.get()
    }

    unsafe fn set_next(&mut self, ptr: Self::LinkPtr, next: Option<Self::LinkPtr>) {
        *ptr.as_ref().next.get() = next;
    }

    unsafe fn set_prev(&mut self, ptr: Self::LinkPtr, prev: Option<Self::LinkPtr>) {
        *ptr.as_ref().prev.get() = prev;
    }
}

#[derive(Clone, Copy)]
pub enum Kind {
    Shared,
    Exclusive,
}

enum State {
    Init,
    Waiting(Waker),
    Woken,
    Finished,
    Processing,
}

// Indicates the queue to which the waiter belongs. It is the responsibility of the Mutex and
// Condvar implementations to update this value when adding/removing a Waiter from their respective
// waiter lists.
#[repr(u8)]
#[derive(Debug, Eq, PartialEq)]
pub enum WaitingFor {
    // The waiter is either not linked into  a waiter list or it is linked into a temporary list.
    None = 0,
    // The waiter is linked into the Mutex's waiter list.
    Mutex = 1,
    // The waiter is linked into the Condvar's waiter list.
    Condvar = 2,
}

// Internal struct used to keep track of the cancellation function.
struct Cancel {
    c: fn(usize, &Waiter, bool) -> bool,
    data: usize,
}

// Represents a thread currently blocked on a Condvar or on acquiring a Mutex.
pub struct Waiter {
    link: AtomicLink,
    state: SpinLock<State>,
    cancel: SpinLock<Cancel>,
    kind: Kind,
    waiting_for: AtomicU8,
}

impl Waiter {
    // Create a new, initialized Waiter.
    //
    // `kind` should indicate whether this waiter represent a thread that is waiting for a shared
    // lock or an exclusive lock.
    //
    // `cancel` is the function that is called when a `WaitFuture` (returned by the `wait()`
    // function) is dropped before it can complete. `cancel_data` is used as the first parameter of
    // the `cancel` function. The second parameter is the `Waiter` that was canceled and the third
    // parameter indicates whether the `WaitFuture` was dropped after it was woken (but before it
    // was polled to completion). The `cancel` function should return true if it was able to
    // successfully process the cancellation. One reason why a `cancel` function may return false is
    // if the `Waiter` was transferred to a different waiter list after the cancel function was
    // called but before it was able to run. In this case, it is expected that the new waiter list
    // updated the cancel function (by calling `set_cancel`) and the cancellation will be retried by
    // fetching and calling the new cancellation function.
    //
    // `waiting_for` indicates the waiter list to which this `Waiter` will be added. See the
    // documentation of the `WaitingFor` enum for the meaning of the different values.
    pub fn new(
        kind: Kind,
        cancel: fn(usize, &Waiter, bool) -> bool,
        cancel_data: usize,
        waiting_for: WaitingFor,
    ) -> Waiter {
        Waiter {
            link: AtomicLink::new(),
            state: SpinLock::new(State::Init),
            cancel: SpinLock::new(Cancel {
                c: cancel,
                data: cancel_data,
            }),
            kind,
            waiting_for: AtomicU8::new(waiting_for as u8),
        }
    }

    // The kind of lock that this `Waiter` is waiting to acquire.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    // Returns true if this `Waiter` is currently linked into a waiter list.
    pub fn is_linked(&self) -> bool {
        self.link.is_linked()
    }

    // Indicates the waiter list to which this `Waiter` belongs.
    pub fn is_waiting_for(&self) -> WaitingFor {
        match self.waiting_for.load(Ordering::Acquire) {
            0 => WaitingFor::None,
            1 => WaitingFor::Mutex,
            2 => WaitingFor::Condvar,
            v => panic!("Unknown value for `WaitingFor`: {}", v),
        }
    }

    // Change the waiter list to which this `Waiter` belongs. This will panic if called when the
    // `Waiter` is still linked into a waiter list.
    pub fn set_waiting_for(&self, waiting_for: WaitingFor) {
        self.waiting_for.store(waiting_for as u8, Ordering::Release);
    }

    // Change the cancellation function that this `Waiter` should use. This will panic if called
    // when the `Waiter` is still linked into a waiter list.
    pub fn set_cancel(&self, c: fn(usize, &Waiter, bool) -> bool, data: usize) {
        debug_assert!(
            !self.is_linked(),
            "Cannot change cancellation function while linked"
        );
        let mut cancel = self.cancel.lock();
        cancel.c = c;
        cancel.data = data;
    }

    // Reset the Waiter back to its initial state. Panics if this `Waiter` is still linked into a
    // waiter list.
    pub fn reset(&self, waiting_for: WaitingFor) {
        debug_assert!(!self.is_linked(), "Cannot reset `Waiter` while linked");
        self.set_waiting_for(waiting_for);

        let mut state = self.state.lock();
        if let State::Waiting(waker) = mem::replace(&mut *state, State::Init) {
            mem::drop(state);
            mem::drop(waker);
        }
    }

    // Wait until woken up by another thread.
    pub fn wait(&self) -> WaitFuture<'_> {
        WaitFuture { waiter: self }
    }

    // Wake up the thread associated with this `Waiter`. Panics if `waiting_for()` does not return
    // `WaitingFor::None` or if `is_linked()` returns true.
    pub fn wake(&self) {
        debug_assert!(!self.is_linked(), "Cannot wake `Waiter` while linked");
        debug_assert_eq!(self.is_waiting_for(), WaitingFor::None);

        let mut state = self.state.lock();

        if let State::Waiting(waker) = mem::replace(&mut *state, State::Woken) {
            mem::drop(state);
            waker.wake();
        }
    }
}

pub struct WaitFuture<'w> {
    waiter: &'w Waiter,
}

impl<'w> Future for WaitFuture<'w> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let mut state = self.waiter.state.lock();

        match mem::replace(&mut *state, State::Processing) {
            State::Init => {
                *state = State::Waiting(cx.waker().clone());

                Poll::Pending
            }
            State::Waiting(old_waker) => {
                *state = State::Waiting(cx.waker().clone());
                mem::drop(state);
                mem::drop(old_waker);

                Poll::Pending
            }
            State::Woken => {
                *state = State::Finished;
                Poll::Ready(())
            }
            State::Finished => {
                panic!("Future polled after returning Poll::Ready");
            }
            State::Processing => {
                panic!("Unexpected waker state");
            }
        }
    }
}

impl<'w> Drop for WaitFuture<'w> {
    fn drop(&mut self) {
        let state = self.waiter.state.lock();

        match *state {
            State::Finished => {}
            State::Processing => panic!("Unexpected waker state"),
            State::Woken => {
                mem::drop(state);

                // We were woken but not polled.  Wake up the next waiter.
                let mut success = false;
                while !success {
                    let cancel = self.waiter.cancel.lock();
                    let c = cancel.c;
                    let data = cancel.data;

                    mem::drop(cancel);

                    success = c(data, self.waiter, true);
                }
            }
            _ => {
                mem::drop(state);

                // Not woken.  No need to wake up any waiters.
                let mut success = false;
                while !success {
                    let cancel = self.waiter.cancel.lock();
                    let c = cancel.c;
                    let data = cancel.data;

                    mem::drop(cancel);

                    success = c(data, self.waiter, false);
                }
            }
        }
    }
}

intrusive_adapter!(pub WaiterAdapter = Arc<Waiter>: Waiter { link: AtomicLink });

pub type WaiterList = LinkedList<WaiterAdapter>;

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::UnsafeCell;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use intrusive_collections::intrusive_adapter;
use intrusive_collections::linked_list::LinkedList;
use intrusive_collections::linked_list::LinkedListOps;
use intrusive_collections::DefaultLinkOps;
use intrusive_collections::LinkOps;

use super::super::sync::SpinLock;

// An atomic version of a LinkedListLink. See https://github.com/Amanieu/intrusive-rs/issues/47 for
// more details.
#[repr(align(128))]
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

// SAFETY:
// Safe because the only way to mutate `AtomicLink` is via the `LinkedListOps` trait whose methods
// are all unsafe and require that the caller has first called `acquire_link` (and had it return
// true) to use them safely.
unsafe impl Send for AtomicLink {}
// SAFETY: See safety comment for impl Send
unsafe impl Sync for AtomicLink {}

#[derive(Copy, Clone, Default)]
pub struct AtomicLinkOps;

// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
unsafe impl LinkOps for AtomicLinkOps {
    type LinkPtr = NonNull<AtomicLink>;

    unsafe fn acquire_link(&mut self, ptr: Self::LinkPtr) -> bool {
        !ptr.as_ref().linked.swap(true, Ordering::Acquire)
    }

    unsafe fn release_link(&mut self, ptr: Self::LinkPtr) {
        ptr.as_ref().linked.store(false, Ordering::Release)
    }
}

// TODO(b/315998194): Add safety comment
#[allow(clippy::undocumented_unsafe_blocks)]
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

// Represents a thread currently blocked on a Condvar or on acquiring a Mutex.
pub struct Waiter {
    link: AtomicLink,
    state: SpinLock<State>,
    cancel: fn(usize, &Waiter, bool),
    cancel_data: usize,
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
    // was polled to completion). A value of `false` for the third parameter may already be stale
    // by the time the cancel function runs and so does not guarantee that the waiter was not woken.
    // In this case, implementations should still check if the Waiter was woken. However, a value of
    // `true` guarantees that the waiter was already woken up so no additional checks are necessary.
    // In this case, the cancel implementation should wake up the next waiter in its wait list, if
    // any.
    //
    // `waiting_for` indicates the waiter list to which this `Waiter` will be added. See the
    // documentation of the `WaitingFor` enum for the meaning of the different values.
    pub fn new(
        kind: Kind,
        cancel: fn(usize, &Waiter, bool),
        cancel_data: usize,
        waiting_for: WaitingFor,
    ) -> Waiter {
        Waiter {
            link: AtomicLink::new(),
            state: SpinLock::new(State::Init),
            cancel,
            cancel_data,
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
                (self.waiter.cancel)(self.waiter.cancel_data, self.waiter, true);
            }
            _ => {
                mem::drop(state);

                // Not woken.  No need to wake up any waiters.
                (self.waiter.cancel)(self.waiter.cancel_data, self.waiter, false);
            }
        }
    }
}

intrusive_adapter!(pub WaiterAdapter = Arc<Waiter>: Waiter { link: AtomicLink });

pub type WaiterList = LinkedList<WaiterAdapter>;

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Waker;
use std::task::{Context, Poll};

use futures::future::FutureExt;

use crate::waker::create_waker;

/// Represents a future executor that can be run. Implementers of the trait will take a list of
/// futures and poll them until completed.
pub trait Executor {
    /// The type returned by the executor. This is normally `()` or a combination of the output the
    /// futures produce.
    type Output;

    /// Run the executor, this will return once the exit criteria is met. The exit criteria is
    /// specified when the executor is created, for example running until all futures are complete.
    fn run(&mut self) -> Self::Output;
}

/// A token returned from `add_waker` that can be used to cancel the waker before it completes.
pub struct WakerToken(pub(crate) u64);

// Tracks if a future needs to be polled and the waker to use.
pub(crate) struct FutureState {
    pub needs_poll: Rc<Cell<bool>>,
    pub waker: Waker,
}

impl FutureState {
    pub fn new() -> FutureState {
        let needs_poll = Rc::new(Cell::new(true));
        // Safe because a valid pointer is passed to `create_waker` and the valid result is
        // passed to `Waker::from_raw`. And because the reference count to needs_poll is
        // incremented by cloning it so it can't be dropped before the waker.
        let waker = unsafe {
            let clone = needs_poll.clone();
            let raw_waker = create_waker(Rc::into_raw(clone) as *const _);
            Waker::from_raw(raw_waker)
        };
        FutureState { needs_poll, waker }
    }
}

// Couples a future owned by the executor with a flag that indicates the future is ready to be
// polled. Futures will start with the flag set. After blocking by returning `Poll::Pending`, the
// flag will be false until the waker is triggered and sets the flag to true, signalling the
// executor to poll the future again.
pub(crate) struct ExecutableFuture<T> {
    future: Pin<Box<dyn Future<Output = T>>>,
    state: FutureState,
}

impl<T> ExecutableFuture<T> {
    // Creates an `ExecutableFuture` from the future. The returned struct is used to track when the
    // future should be polled again.
    pub fn new(future: Pin<Box<dyn Future<Output = T>>>) -> ExecutableFuture<T> {
        ExecutableFuture {
            future,
            state: FutureState::new(),
        }
    }

    // Polls the future if needed and returns the result.
    // Covers setting up the waker and context before calling the future.
    fn poll(&mut self) -> Poll<T> {
        let mut ctx = Context::from_waker(&self.state.waker);
        let f = self.future.as_mut();
        f.poll(&mut ctx)
    }
}

// Private trait used to allow one executor to behave differently.  Using FutureList allows the
// executor code to be common across different collections of crates and different termination
// behavior. For example, one list can decide to exit after the first trait completes, others can
// wait until all are complete.
pub(crate) trait FutureList {
    type Output;

    // Return a mutable reference to the list of futures that can be added or removed from this
    // List.
    fn futures_mut(&mut self) -> &mut UnitFutures;
    // Polls all futures that are ready. Returns the results if this list has completed.
    fn poll_results(&mut self) -> Option<Self::Output>;
    // Returns true if any future in the list is ready to be polled.
    fn any_ready(&self) -> bool;
}

// `UnitFutures` is the simplest implementor of `FutureList`. It runs all futures added to it until
// there are none left to poll. The futures must all return `()`.
pub(crate) struct UnitFutures {
    futures: VecDeque<ExecutableFuture<()>>,
}

impl UnitFutures {
    // Creates a new, empty list of futures.
    pub fn new() -> UnitFutures {
        UnitFutures {
            futures: VecDeque::new(),
        }
    }

    // Adds a future to the list of futures to be polled.
    pub fn append(&mut self, futures: &mut VecDeque<ExecutableFuture<()>>) {
        self.futures.append(futures);
    }

    // Polls all futures that are ready to be polled. Removes any futures that indicate they are
    // completed.
    pub fn poll_all(&mut self) {
        let mut i = 0;
        while i < self.futures.len() {
            let fut = &mut self.futures[i];
            let remove = if fut.state.needs_poll.replace(false) {
                fut.poll().is_ready()
            } else {
                false
            };
            if remove {
                self.futures.remove(i);
            } else {
                i += 1;
            }
        }
    }
}

impl FutureList for UnitFutures {
    type Output = ();

    fn futures_mut(&mut self) -> &mut UnitFutures {
        self
    }

    fn poll_results(&mut self) -> Option<Self::Output> {
        self.poll_all();
        if self.futures.is_empty() {
            Some(())
        } else {
            None
        }
    }

    fn any_ready(&self) -> bool {
        self.futures.iter().any(|fut| fut.state.needs_poll.get())
    }
}

// Execute one future until it completes.
pub(crate) struct RunOne<F: Future + Unpin> {
    fut: F,
    fut_state: FutureState,
    added_futures: UnitFutures,
}

impl<F: Future + Unpin> RunOne<F> {
    pub fn new(f: F) -> RunOne<F> {
        RunOne {
            fut: f,
            fut_state: FutureState::new(),
            added_futures: UnitFutures::new(),
        }
    }
}

impl<F: Future + Unpin> FutureList for RunOne<F> {
    type Output = F::Output;

    fn futures_mut(&mut self) -> &mut UnitFutures {
        &mut self.added_futures
    }

    fn poll_results(&mut self) -> Option<Self::Output> {
        let _ = self.added_futures.poll_results();

        if self.fut_state.needs_poll.replace(false) {
            let mut ctx = Context::from_waker(&self.fut_state.waker);
            // The future impls `Unpin`, use `poll_unpin` to avoid wrapping it in
            // `Pin` to call `poll`.
            if let Poll::Ready(o) = self.fut.poll_unpin(&mut ctx) {
                return Some(o);
            }
        };
        None
    }

    fn any_ready(&self) -> bool {
        self.added_futures.any_ready() || self.fut_state.needs_poll.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn basic_run() {
        async fn f(called: Rc<AtomicUsize>) {
            called.fetch_add(1, Ordering::Relaxed);
        }

        let f1_called = Rc::new(AtomicUsize::new(0));
        let f2_called = Rc::new(AtomicUsize::new(0));

        let fut1 = Box::pin(f(f1_called.clone()));
        let fut2 = Box::pin(f(f2_called.clone()));

        let mut futures = VecDeque::new();
        futures.push_back(ExecutableFuture::new(fut1));
        futures.push_back(ExecutableFuture::new(fut2));

        let mut uf = UnitFutures::new();
        uf.append(&mut futures);
        assert!(uf.poll_results().is_some());
        assert_eq!(f1_called.load(Ordering::Relaxed), 1);
        assert_eq!(f2_called.load(Ordering::Relaxed), 1);
    }
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The executor runs all given futures to completion. Futures register wakers associated with file
//! descriptors. The wakers will be called when the FD becomes readable or writable depending on
//! the situation.
//!
//! `FdExecutor` is meant to be used with the `futures-rs` crate that provides combinators and
//! utility functions to combine futures.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::fs::File;
use std::future::Future;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::task::Waker;

use slab::Slab;

use sys_util::{PollContext, WatchingEvents};

use crate::executor::{ExecutableFuture, Executor, FutureList};
use crate::WakerToken;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Attempts to create two Executors on the same thread fail.
    AttemptedDuplicateExecutor,
    /// Failed to copy the FD for the polling context.
    DuplicatingFd(sys_util::Error),
    /// Failed accessing the thread local storage for wakers.
    InvalidContext,
    /// Creating a context to wait on FDs failed.
    CreatingContext(sys_util::Error),
    /// PollContext failure.
    PollContextError(sys_util::Error),
    /// Failed to submit the waker to the polling context.
    SubmittingWaker(sys_util::Error),
    /// A Waker was canceled, but the operation isn't running.
    UnknownWaker,
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            AttemptedDuplicateExecutor => write!(f, "Cannot have two executors on one thread."),
            DuplicatingFd(e) => write!(f, "Failed to copy the FD for the polling context: {}", e),
            InvalidContext => write!(
                f,
                "Invalid context, was the Fd executor created successfully?"
            ),
            CreatingContext(e) => write!(f, "An error creating the fd waiting context: {}.", e),
            PollContextError(e) => write!(f, "PollContext failure: {}", e),
            SubmittingWaker(e) => write!(f, "An error adding to the Aio context: {}.", e),
            UnknownWaker => write!(f, "Unknown waker"),
        }
    }
}

// Temporary vectors of new additions to the executor.

// Tracks active wakers and the futures they are associated with.
thread_local!(static STATE: RefCell<Option<FdWakerState>> = RefCell::new(None));

fn add_waker(fd: RawFd, waker: Waker, events: WatchingEvents) -> Result<WakerToken> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(state) = state.as_mut() {
            state.add_waker(fd, waker, events)
        } else {
            Err(Error::InvalidContext)
        }
    })
}

/// A token returned from `add_waker` that can be used to cancel the waker before it completes.
/// Used to manage getting the result from the underlying executor for a completed operation.
/// Dropping a `PendingWaker` will get the result from the executor.
pub struct PendingWaker {
    token: Option<WakerToken>,
}

impl PendingWaker {
    pub(crate) fn new(token: WakerToken) -> PendingWaker {
        PendingWaker { token: Some(token) }
    }
}

impl Drop for PendingWaker {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = cancel_waker(token);
        }
    }
}

/// Tells the waking system to wake `waker` when `fd` becomes readable.
/// The 'fd' must be fully owned by the future adding the waker, and must not be closed until the
/// next time the future is polled. If the fd is closed, there is a race where another FD can be
/// opened on top of it causing the next poll to access the new target file.
/// Returns a `PendingWaker` that can be used to poll for completion or cancel the waker before it
/// completes.
pub(crate) fn add_read_waker(fd: RawFd, waker: Waker) -> Result<PendingWaker> {
    add_waker(fd, waker, WatchingEvents::empty().set_read()).map(PendingWaker::new)
}

/// Tells the waking system to wake `waker` when `fd` becomes writable.
/// The 'fd' must be fully owned by the future adding the waker, and must not be closed until the
/// next time the future is polled. If the fd is closed, there is a race where another FD can be
/// opened on top of it causing the next poll to access the new target file.
/// Returns a `PendingWaker` that can be used to poll for completion or cancel the waker before it
/// completes.
pub(crate) fn add_write_waker(fd: RawFd, waker: Waker) -> Result<PendingWaker> {
    add_waker(fd, waker, WatchingEvents::empty().set_write()).map(PendingWaker::new)
}

/// Cancels the waker that returned the given token if the waker hasn't yet fired.
pub(crate) fn cancel_waker(token: WakerToken) -> Result<()> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(state) = state.as_mut() {
            state.cancel_waker(token)
        } else {
            Err(Error::InvalidContext)
        }
    })
}

/// Adds a new top level future to the Executor.
/// These futures must return `()`, indicating they are intended to create side-effects only.
pub(crate) fn add_future(future: Pin<Box<dyn Future<Output = ()>>>) -> Result<()> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(state) = state.as_mut() {
            state.new_futures.push_back(ExecutableFuture::new(future));
            Ok(())
        } else {
            Err(Error::InvalidContext)
        }
    })
}

// Tracks active wakers and associates wakers with the futures that registered them.
struct FdWakerState {
    poll_ctx: PollContext<usize>,
    tokens: Slab<(File, Waker)>,
    new_futures: VecDeque<ExecutableFuture<()>>,
}

impl FdWakerState {
    fn new() -> Result<Self> {
        Ok(FdWakerState {
            poll_ctx: PollContext::new().map_err(Error::CreatingContext)?,
            tokens: Slab::with_capacity(64),
            new_futures: VecDeque::new(),
        })
    }

    // Adds an fd that, when signaled, will trigger the given waker.
    fn add_waker(&mut self, fd: RawFd, waker: Waker, events: WatchingEvents) -> Result<WakerToken> {
        let duped_fd = unsafe {
            // Safe because duplicating an FD doesn't affect memory safety, and the dup'd FD
            // will only be added to the poll loop.
            File::from_raw_fd(dup_fd(fd)?)
        };
        let entry = self.tokens.vacant_entry();
        let next_token = entry.key();
        self.poll_ctx
            .add_fd_with_events(&duped_fd, events, next_token)
            .map_err(Error::SubmittingWaker)?;
        entry.insert((duped_fd, waker));
        Ok(WakerToken(next_token))
    }

    // Waits until one of the FDs is readable and wakes the associated waker.
    fn wait_wake_event(&mut self) -> Result<()> {
        let events = self.poll_ctx.wait().map_err(Error::PollContextError)?;
        for e in events.iter() {
            let token = e.token();
            let (fd, waker) = self.tokens.remove(token);
            self.poll_ctx.delete(&fd).map_err(Error::PollContextError)?;
            waker.wake();
        }
        Ok(())
    }

    // Remove the waker for the given token if it hasn't fired yet.
    fn cancel_waker(&mut self, token: WakerToken) -> Result<()> {
        let (fd, _waker) = self.tokens.remove(token.0);
        self.poll_ctx.delete(&fd).map_err(Error::PollContextError)?;
        Ok(())
    }
}

/// Runs futures to completion on a single thread. Futures are allowed to block on file descriptors
/// only. Futures can only block on FDs becoming readable or writable. `FdExecutor` is meant to be
/// used where a poll or select loop would be used otherwise.
pub(crate) struct FdExecutor<T: FutureList> {
    futures: T,
}

impl<T: FutureList> Executor for FdExecutor<T> {
    type Output = Result<T::Output>;

    fn run(&mut self) -> Self::Output {
        self.append_futures();

        loop {
            if let Some(output) = self.futures.poll_results() {
                return Ok(output);
            }

            self.append_futures();

            // If no futures are ready, sleep until a waker is signaled.
            if !self.futures.any_ready() {
                STATE.with(|state| {
                    let mut state = state.borrow_mut();
                    if let Some(state) = state.as_mut() {
                        state.wait_wake_event()?;
                    } else {
                        unreachable!("Can't get here without a context being created");
                    }
                    Ok(())
                })?;
            }
        }
    }
}

impl<T: FutureList> FdExecutor<T> {
    /// Create a new executor.
    pub fn new(futures: T) -> Result<FdExecutor<T>> {
        STATE.with(|state| {
            if state.borrow().is_some() {
                return Err(Error::AttemptedDuplicateExecutor);
            }
            state.replace(Some(FdWakerState::new()?));
            Ok(())
        })?;
        Ok(FdExecutor { futures })
    }

    // Add any new futures and wakers to the lists.
    fn append_futures(&mut self) {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if let Some(state) = state.as_mut() {
                self.futures.futures_mut().append(&mut state.new_futures);
            } else {
                unreachable!("Can't get here without a context being created");
            }
        });
    }
}

impl<T: FutureList> Drop for FdExecutor<T> {
    fn drop(&mut self) {
        STATE.with(|state| {
            state.replace(None);
        });
    }
}

// Used to `dup` the FDs passed to the executor so there is a guarantee they aren't closed while
// waiting in TLS to be added to the main polling context.
unsafe fn dup_fd(fd: RawFd) -> Result<RawFd> {
    let ret = libc::dup(fd);
    if ret < 0 {
        Err(Error::DuplicatingFd(sys_util::Error::last()))
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::fs::File;
    use std::future::Future;
    use std::os::unix::io::AsRawFd;
    use std::rc::Rc;
    use std::task::{Context, Poll};

    use futures::future::Either;

    use super::*;

    // test function to get the number of pending wakers.
    fn pending_ops() -> usize {
        STATE.with(|state| {
            let state = state.borrow_mut();
            state.as_ref().unwrap().tokens.len()
        })
    }

    struct TestFut {
        f: File,
        pending_waker: Option<PendingWaker>,
    }

    impl TestFut {
        fn new(f: File) -> TestFut {
            TestFut {
                f,
                pending_waker: None,
            }
        }
    }

    impl Future for TestFut {
        type Output = u64;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            if self.pending_waker.is_none() {
                println!("pend");
                self.pending_waker = Some(
                    crate::fd_executor::add_read_waker(self.f.as_raw_fd(), cx.waker().clone())
                        .unwrap(),
                );
            }
            Poll::Pending
        }
    }

    impl Drop for TestFut {
        fn drop(&mut self) {
            println!("drop test fut");
        }
    }

    #[test]
    fn test_it() {
        async fn do_test() {
            let (r, _w) = sys_util::pipe(true).unwrap();
            let done = Box::pin(async { 5usize });
            let pending = Box::pin(TestFut::new(r));
            match futures::future::select(pending, done).await {
                Either::Right((5, pending)) => std::mem::drop(pending),
                _ => panic!("unexpected select result"),
            }
            // test that dropping the incomplete future removed the waker.
            assert_eq!(0, pending_ops());
        }

        let fut = do_test();

        crate::run_one_poll(Box::pin(fut)).unwrap();

        // Example of starting the framework and running a future:
        async fn my_async(x: Rc<RefCell<u64>>) {
            x.replace(4);
        }

        let x = Rc::new(RefCell::new(0));
        crate::run_one_poll(Box::pin(my_async(x.clone()))).unwrap();
        assert_eq!(*x.borrow(), 4);
    }
}

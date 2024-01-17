// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! An Executor and future combinators based on operations that block on file descriptors.
//!
//! This crate is meant to be used with the `futures-rs` crate that provides further combinators
//! and utility functions to combine and manage futures. All futures will run until they block on a
//! file descriptor becoming readable or writable. Facilities are provided to register future
//! wakers based on such events.
//!
//! # Running top-level futures.
//!
//! Use helper functions based the desired behavior of your application.
//!
//! ## Completing one of several futures.
//!
//! If there are several top level tasks that should run until any one completes, use the "select"
//! family of executor constructors. These return an [`Executor`](trait.Executor.html) whose `run`
//! function will return when the first future completes. The uncompleted futures will also be
//! returned so they can be run further or otherwise cleaned up. These functions are inspired by
//! the `select_all` function from futures-rs, but built to be run inside an FD based executor and
//! to poll only when necessary. See the docs for [`select2`](fn.select2.html),
//! [`select3`](fn.select3.html), [`select4`](fn.select4.html), and [`select5`](fn.select5.html).
//!
//! ## Completing all of several futures.
//!
//! If there are several top level tasks that all need to be completed, use the "complete" family
//! of executor constructors. These return an [`Executor`](trait.Executor.html) whose `run`
//! function will return only once all the futures passed to it have completed. These functions are
//! inspired by the `join_all` function from futures-rs, but built to be run inside an FD based
//! executor and to poll only when necessary. See the docs for [`complete2`](fn.complete2.html),
//! [`complete3`](fn.complete3.html), [`complete4`](fn.complete4.html), and
//! [`complete5`](fn.complete5.html).
//!
//! # Implementing new FD-based futures.
//!
//! For URing implementations should provide an implementation of the `IoSource` trait.
//! For the FD executor, new futures can use the existing ability to poll a source to build async
//! functionality on top of.
//!
//! # Implementations
//!
//! Currently there are two paths for using the asynchronous IO. One uses a WaitContext and drives
//! futures based on the FDs signaling they are ready for the opteration. This method will exist so
//! long as kernels < 5.4 are supported.
//! The other method submits operations to io_uring and is signaled when they complete. This is more
//! efficient, but only supported on kernel 5.4+.
//! If `IoSource::new` is used to interface with async IO, then the correct backend will be chosen
//! automatically.
//!
//! # Examples
//!
//! See the docs for `IoSource` if support for kernels <5.4 is required. Focus on `UringSource` if
//! all systems have support for io_uring.

mod async_types;
pub mod audio_streams_async;
mod blocking;
mod complete;
mod event;
mod executor;
mod io_ext;
mod io_source;
pub mod mem;
mod queue;
mod select;
pub mod sync;
pub mod sys;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use sys::linux::uring_executor::is_uring_stable;
pub use sys::Executor;
mod common_executor;
mod timer;
mod waker;

use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

pub use async_types::*;
pub use base::Event;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use blocking::sys::linux::block_on::block_on;
pub use blocking::unblock;
pub use blocking::unblock_disarm;
pub use blocking::BlockingPool;
pub use blocking::CancellableBlockingPool;
pub use blocking::TimeoutAction;
pub use event::EventAsync;
pub use executor::ExecutorKind;
pub use executor::TaskHandle;
#[cfg(windows)]
pub use futures::executor::block_on;
use futures::stream::FuturesUnordered;
pub use io_ext::AsyncError;
pub use io_ext::AsyncResult;
pub use io_ext::AsyncWrapper;
pub use io_ext::IntoAsync;
pub use io_source::IoSource;
pub use mem::BackingMemory;
pub use mem::MemRegion;
pub use mem::MemRegionIter;
pub use mem::VecIoWrapper;
use remain::sorted;
pub use select::SelectResult;
use thiserror::Error as ThisError;
pub use timer::TimerAsync;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Error from EventAsync
    #[error("Failure in EventAsync: {0}")]
    EventAsync(base::Error),
    /// Error from the handle executor.
    #[cfg(windows)]
    #[error("Failure in the handle executor: {0}")]
    HandleExecutor(sys::windows::handle_executor::Error),
    #[error("IO error: {0}")]
    Io(std::io::Error),
    /// Error from the polled(FD) source, which includes error from the FD executor.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("An error with a poll source: {0}")]
    PollSource(sys::linux::poll_source::Error),
    /// Error from Timer.
    #[error("Failure in Timer: {0}")]
    Timer(base::Error),
    /// Error from TimerFd.
    #[error("Failure in TimerAsync: {0}")]
    TimerAsync(AsyncError),
    /// Error from the uring executor.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[error("Failure in the uring executor: {0}")]
    URingExecutor(sys::linux::uring_executor::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Heterogeneous collection of `async_task:Task` that are running in a "detached" state.
///
/// We keep them around to ensure they are dropped before the executor they are running on.
pub(crate) struct DetachedTasks(FuturesUnordered<Pin<Box<dyn Future<Output = ()> + Send>>>);

impl DetachedTasks {
    pub(crate) fn new() -> Self {
        DetachedTasks(FuturesUnordered::new())
    }

    pub(crate) fn push<R: Send + 'static>(&self, task: async_task::Task<R>) {
        // Convert to fallible, otherwise poll could panic if the `Runnable` is dropped early.
        let task = task.fallible();
        self.0.push(Box::pin(async {
            let _ = task.await;
        }));
    }

    /// Polls all the tasks, dropping any that complete.
    pub(crate) fn poll(&mut self, cx: &mut std::task::Context) {
        use futures::Stream;
        while let Poll::Ready(Some(_)) = Pin::new(&mut self.0).poll_next(cx) {}
    }
}

// Select helpers to run until any future completes.

/// Creates a combinator that runs the two given futures until one completes, returning a tuple
/// containing the result of the finished future and the still pending future.
///
///  # Example
///
///    ```
///    use cros_async::{SelectResult, select2, block_on};
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {let () = pending().await;};
///    pin_mut!(first);
///    pin_mut!(second);
///    match block_on(select2(first, second)) {
///        (SelectResult::Finished(5), SelectResult::Pending(_second)) => (),
///        _ => panic!("Select didn't return the first future"),
///    };
///    ```
pub async fn select2<F1: Future + Unpin, F2: Future + Unpin>(
    f1: F1,
    f2: F2,
) -> (SelectResult<F1>, SelectResult<F2>) {
    select::Select2::new(f1, f2).await
}

/// Creates a combinator that runs the three given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{SelectResult, select3, block_on};
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {4};
///    let second = async {let () = pending().await;};
///    let third = async {5};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    match block_on(select3(first, second, third)) {
///        (SelectResult::Finished(4),
///         SelectResult::Pending(_second),
///         SelectResult::Finished(5)) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub async fn select3<F1: Future + Unpin, F2: Future + Unpin, F3: Future + Unpin>(
    f1: F1,
    f2: F2,
    f3: F3,
) -> (SelectResult<F1>, SelectResult<F2>, SelectResult<F3>) {
    select::Select3::new(f1, f2, f3).await
}

/// Creates a combinator that runs the four given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{SelectResult, select4, block_on};
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {4};
///    let second = async {let () = pending().await;};
///    let third = async {5};
///    let fourth = async {let () = pending().await;};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    pin_mut!(fourth);
///    match block_on(select4(first, second, third, fourth)) {
///        (SelectResult::Finished(4), SelectResult::Pending(_second),
///         SelectResult::Finished(5), SelectResult::Pending(_fourth)) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub async fn select4<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
) {
    select::Select4::new(f1, f2, f3, f4).await
}

/// Creates a combinator that runs the five given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{SelectResult, select5, block_on};
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {4};
///    let second = async {let () = pending().await;};
///    let third = async {5};
///    let fourth = async {let () = pending().await;};
///    let fifth = async {6};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    pin_mut!(fourth);
///    pin_mut!(fifth);
///    match block_on(select5(first, second, third, fourth, fifth)) {
///        (SelectResult::Finished(4), SelectResult::Pending(_second),
///         SelectResult::Finished(5), SelectResult::Pending(_fourth),
///         SelectResult::Finished(6)) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub async fn select5<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
) {
    select::Select5::new(f1, f2, f3, f4, f5).await
}

/// Creates a combinator that runs the six given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{SelectResult, select6, block_on};
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {1};
///    let second = async {let () = pending().await;};
///    let third = async {3};
///    let fourth = async {let () = pending().await;};
///    let fifth = async {5};
///    let sixth = async {6};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    pin_mut!(fourth);
///    pin_mut!(fifth);
///    pin_mut!(sixth);
///    match block_on(select6(first, second, third, fourth, fifth, sixth)) {
///        (SelectResult::Finished(1), SelectResult::Pending(_second),
///         SelectResult::Finished(3), SelectResult::Pending(_fourth),
///         SelectResult::Finished(5), SelectResult::Finished(6)) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub async fn select6<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
) {
    select::Select6::new(f1, f2, f3, f4, f5, f6).await
}

pub async fn select7<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
) {
    select::Select7::new(f1, f2, f3, f4, f5, f6, f7).await
}

pub async fn select8<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
    F8: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
    f8: F8,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
    SelectResult<F8>,
) {
    select::Select8::new(f1, f2, f3, f4, f5, f6, f7, f8).await
}

pub async fn select9<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
    F8: Future + Unpin,
    F9: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
    f8: F8,
    f9: F9,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
    SelectResult<F8>,
    SelectResult<F9>,
) {
    select::Select9::new(f1, f2, f3, f4, f5, f6, f7, f8, f9).await
}

pub async fn select10<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
    F8: Future + Unpin,
    F9: Future + Unpin,
    F10: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
    f8: F8,
    f9: F9,
    f10: F10,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
    SelectResult<F8>,
    SelectResult<F9>,
    SelectResult<F10>,
) {
    select::Select10::new(f1, f2, f3, f4, f5, f6, f7, f8, f9, f10).await
}

pub async fn select11<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
    F8: Future + Unpin,
    F9: Future + Unpin,
    F10: Future + Unpin,
    F11: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
    f8: F8,
    f9: F9,
    f10: F10,
    f11: F11,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
    SelectResult<F8>,
    SelectResult<F9>,
    SelectResult<F10>,
    SelectResult<F11>,
) {
    select::Select11::new(f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11).await
}

pub async fn select12<
    F1: Future + Unpin,
    F2: Future + Unpin,
    F3: Future + Unpin,
    F4: Future + Unpin,
    F5: Future + Unpin,
    F6: Future + Unpin,
    F7: Future + Unpin,
    F8: Future + Unpin,
    F9: Future + Unpin,
    F10: Future + Unpin,
    F11: Future + Unpin,
    F12: Future + Unpin,
>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
    f6: F6,
    f7: F7,
    f8: F8,
    f9: F9,
    f10: F10,
    f11: F11,
    f12: F12,
) -> (
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
    SelectResult<F6>,
    SelectResult<F7>,
    SelectResult<F8>,
    SelectResult<F9>,
    SelectResult<F10>,
    SelectResult<F11>,
    SelectResult<F12>,
) {
    select::Select12::new(f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12).await
}

// Combination helpers to run until all futures are complete.

/// Creates a combinator that runs the two given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{complete2, block_on};
///
///    let first = async {5};
///    let second = async {6};
///    assert_eq!(block_on(complete2(first, second)), (5,6));
///    ```
pub async fn complete2<F1, F2>(f1: F1, f2: F2) -> (F1::Output, F2::Output)
where
    F1: Future,
    F2: Future,
{
    complete::Complete2::new(f1, f2).await
}

/// Creates a combinator that runs the three given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{complete3, block_on};
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    assert_eq!(block_on(complete3(first, second, third)), (5,6,7));
///    ```
pub async fn complete3<F1, F2, F3>(f1: F1, f2: F2, f3: F3) -> (F1::Output, F2::Output, F3::Output)
where
    F1: Future,
    F2: Future,
    F3: Future,
{
    complete::Complete3::new(f1, f2, f3).await
}

/// Creates a combinator that runs the four given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{complete4, block_on};
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    let fourth = async {8};
///    assert_eq!(block_on(complete4(first, second, third, fourth)), (5,6,7,8));
///    ```
pub async fn complete4<F1, F2, F3, F4>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
) -> (F1::Output, F2::Output, F3::Output, F4::Output)
where
    F1: Future,
    F2: Future,
    F3: Future,
    F4: Future,
{
    complete::Complete4::new(f1, f2, f3, f4).await
}

/// Creates a combinator that runs the five given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{complete5, block_on};
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    let fourth = async {8};
///    let fifth = async {9};
///    assert_eq!(block_on(complete5(first, second, third, fourth, fifth)),
///               (5,6,7,8,9));
///    ```
pub async fn complete5<F1, F2, F3, F4, F5>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
    f5: F5,
) -> (F1::Output, F2::Output, F3::Output, F4::Output, F5::Output)
where
    F1: Future,
    F2: Future,
    F3: Future,
    F4: Future,
    F5: Future,
{
    complete::Complete5::new(f1, f2, f3, f4, f5).await
}

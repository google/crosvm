// Copyright 2020 The Chromium OS Authors. All rights reserved.
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
//! ## Many futures all returning `()`
//!
//! It there are futures that produce side effects and return `()`, the
//! [`empty_executor`](fn.empty_executor.html) function provides an Executor that runs futures
//! returning `()`. Futures are added using the [`add_future`](fn.add_future.html) function.
//!
//! # Implementing new FD-based futures.
//!
//! When building futures to be run in an `FdExecutor` framework, use the following helper
//! functions to perform common tasks:
//!
//! [`add_read_waker`](fn.add_read_waker.html) - Used to associate a provided FD becoming readable
//! with the future being woken. Used before returning Poll::Pending from a future that waits until
//! an FD is writable.
//!
//! [`add_write_waker`](fn.add_write_waker.html) - Used to associate a provided FD becoming
//! writable with the future being woken. Used before returning Poll::Pending from a future that
//! waits until an FD is readable.
//!
//! [`add_future`](fn.add_future.html) - Used to add a new future to the top-level list of running
//! futures.

mod complete;
mod executor;
pub mod fd_executor;
mod select;
mod waker;

pub use executor::Executor;
pub use select::SelectResult;

use executor::UnitFutures;
use fd_executor::{FdExecutor, Result};
use std::future::Future;

/// Creates an empty FdExecutor that can have futures returning `()` added via
/// [`add_future`](fn.add_future.html).
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor};
///    use cros_async::fd_executor::add_future;
///    use futures::future::pending;
///
///    let fut = async { () };
///    let mut ex = empty_executor().expect("Failed to create executor");
///
///    add_future(Box::pin(fut));
///    ex.run();
///    ```
pub fn empty_executor() -> Result<impl Executor> {
    FdExecutor::new(UnitFutures::new())
}

// Select helpers to run until any future completes.

/// Creates an executor that runs the two given futures until one completes, returning a tuple
/// containing the result of the finished future and the still pending future.
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, select2, SelectResult};
///    use cros_async::fd_executor::add_future;
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {let () = pending().await;};
///    pin_mut!(first);
///    pin_mut!(second);
///    match select2(first, second) {
///        Ok((SelectResult::Finished(5), SelectResult::Pending(_second))) => (),
///        _ => panic!("Select didn't return the first future"),
///    };
///    ```
pub fn select2<F1: Future + Unpin, F2: Future + Unpin>(
    f1: F1,
    f2: F2,
) -> Result<(SelectResult<F1>, SelectResult<F2>)> {
    FdExecutor::new(select::Select2::new(f1, f2)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the three given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, select3, SelectResult};
///    use cros_async::fd_executor::add_future;
///    use futures::future::pending;
///    use futures::pin_mut;
///
///    let first = async {4};
///    let second = async {let () = pending().await;};
///    let third = async {5};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    match select3(first, second, third) {
///        Ok((SelectResult::Finished(4),
///            SelectResult::Pending(_second),
///            SelectResult::Finished(5))) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub fn select3<F1: Future + Unpin, F2: Future + Unpin, F3: Future + Unpin>(
    f1: F1,
    f2: F2,
    f3: F3,
) -> Result<(SelectResult<F1>, SelectResult<F2>, SelectResult<F3>)> {
    FdExecutor::new(select::Select3::new(f1, f2, f3)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the four given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, select4, SelectResult};
///    use cros_async::fd_executor::add_future;
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
///    match select4(first, second, third, fourth) {
///        Ok((SelectResult::Finished(4), SelectResult::Pending(_second),
///            SelectResult::Finished(5), SelectResult::Pending(_fourth))) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub fn select4<F1: Future + Unpin, F2: Future + Unpin, F3: Future + Unpin, F4: Future + Unpin>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
) -> Result<(
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
)> {
    FdExecutor::new(select::Select4::new(f1, f2, f3, f4)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the five given futures until one or more completes, returning a
/// tuple containing the result of the finished future(s) and the still pending future(s).
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, select5, SelectResult};
///    use cros_async::fd_executor::add_future;
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
///    match select5(first, second, third, fourth, fifth) {
///        Ok((SelectResult::Finished(4), SelectResult::Pending(_second),
///            SelectResult::Finished(5), SelectResult::Pending(_fourth),
///            SelectResult::Finished(6))) => (),
///        _ => panic!("Select didn't return the futures"),
///    };
///    ```
pub fn select5<
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
) -> Result<(
    SelectResult<F1>,
    SelectResult<F2>,
    SelectResult<F3>,
    SelectResult<F4>,
    SelectResult<F5>,
)> {
    FdExecutor::new(select::Select5::new(f1, f2, f3, f4, f5)).and_then(|mut f| f.run())
}

// Combination helpers to run until all futures are complete.

/// Creates an executor that runs the two given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, complete2};
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {6};
///    pin_mut!(first);
///    pin_mut!(second);
///    assert_eq!(complete2(first, second).unwrap_or((0,0)), (5,6));
///    ```
pub fn complete2<F1: Future + Unpin, F2: Future + Unpin>(
    f1: F1,
    f2: F2,
) -> Result<(F1::Output, F2::Output)> {
    FdExecutor::new(complete::Complete2::new(f1, f2)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the three given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, complete3};
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    assert_eq!(complete3(first, second, third).unwrap_or((0,0,0)), (5,6,7));
///    ```
pub fn complete3<F1: Future + Unpin, F2: Future + Unpin, F3: Future + Unpin>(
    f1: F1,
    f2: F2,
    f3: F3,
) -> Result<(F1::Output, F2::Output, F3::Output)> {
    FdExecutor::new(complete::Complete3::new(f1, f2, f3)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the four given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, complete4};
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    let fourth = async {8};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    pin_mut!(fourth);
///    assert_eq!(complete4(first, second, third, fourth).unwrap_or((0,0,0,0)), (5,6,7,8));
///    ```
pub fn complete4<F1: Future + Unpin, F2: Future + Unpin, F3: Future + Unpin, F4: Future + Unpin>(
    f1: F1,
    f2: F2,
    f3: F3,
    f4: F4,
) -> Result<(F1::Output, F2::Output, F3::Output, F4::Output)> {
    FdExecutor::new(complete::Complete4::new(f1, f2, f3, f4)).and_then(|mut f| f.run())
}

/// Creates an executor that runs the five given futures to completion, returning a tuple of the
/// outputs each yields.
///
///  # Example
///
///    ```
///    use cros_async::{empty_executor, Executor, complete5};
///    use futures::pin_mut;
///
///    let first = async {5};
///    let second = async {6};
///    let third = async {7};
///    let fourth = async {8};
///    let fifth = async {9};
///    pin_mut!(first);
///    pin_mut!(second);
///    pin_mut!(third);
///    pin_mut!(fourth);
///    pin_mut!(fifth);
///    assert_eq!(complete5(first, second, third, fourth, fifth).unwrap_or((0,0,0,0,0)),
///               (5,6,7,8,9));
///    ```
pub fn complete5<
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
) -> Result<(F1::Output, F2::Output, F3::Output, F4::Output, F5::Output)> {
    FdExecutor::new(complete::Complete5::new(f1, f2, f3, f4, f5)).and_then(|mut f| f.run())
}

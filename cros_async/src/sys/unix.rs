// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_types;
pub mod event;
pub mod executor;
pub mod fd_executor;
pub mod poll_source;
pub mod uring_executor;
pub mod uring_source;
pub use fd_executor::FdExecutor;
pub use fd_executor::FdExecutorTaskHandle;
pub use poll_source::Error as PollSourceError;
pub use poll_source::PollSource;
pub use uring_executor::URingExecutor;
pub use uring_executor::UringExecutorTaskHandle;
pub use uring_source::UringSource;
mod timer;

use std::future::Future;

use crate::AsyncError;
use crate::Error;
use crate::Executor;
use crate::Result;

/// Creates a URingExecutor that runs one future to completion.
///
///  # Example
///
///    ```no_run
///    use cros_async::sys::unix::run_one_uring;
///
///    let fut = async { 55 };
///    assert_eq!(55, run_one_uring(fut).unwrap());
///    ```
pub fn run_one_uring<F: Future>(fut: F) -> Result<F::Output> {
    URingExecutor::new()
        .and_then(|ex| ex.run_until(fut))
        .map_err(Error::URingExecutor)
}

/// Creates a FdExecutor that runs one future to completion.
///
///  # Example
///
///    ```
///    use cros_async::sys::unix::run_one_poll;
///
///    let fut = async { 55 };
///    assert_eq!(55, run_one_poll(fut).unwrap());
///    ```
pub fn run_one_poll<F: Future>(fut: F) -> Result<F::Output> {
    FdExecutor::new()
        .and_then(|ex| ex.run_until(fut))
        .map_err(|e| Error::PollSource(PollSourceError::Executor(e)))
}

/// Creates an Executor that runs one future to completion.
///
///  # Example
///
///    ```
///    use cros_async::sys::unix::run_one;
///
///    let fut = async { 55 };
///    assert_eq!(55, run_one(fut).unwrap());
///    ```
pub fn run_one<F: Future>(fut: F) -> Result<F::Output> {
    Executor::new()
        .and_then(|ex| ex.run_until(fut))
        .map_err(|e| match e {
            AsyncError::EventAsync(e) => Error::EventAsync(e),
            AsyncError::Uring(e) => Error::URingExecutor(e),
            AsyncError::Poll(e) => Error::PollSource(e),
        })
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            URingExecutor(e) => e.into(),
            PollSource(e) => e.into(),
            Timer(e) => e.into(),
            TimerAsync(e) => e.into(),
        }
    }
}

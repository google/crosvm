// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_types;
pub mod event;
pub mod executor;
pub mod handle_executor;
pub mod handle_source;
mod io_completion_port;
pub mod overlapped_source;
mod timer;
pub mod wait_for_handle;
use std::future::Future;

pub use handle_executor::HandleExecutor;
pub use handle_executor::HandleExecutorTaskHandle;
pub use handle_source::HandleSource;
pub use handle_source::HandleWrapper;
pub(crate) use wait_for_handle::WaitForHandle;

use crate::Error;
use crate::Result;

pub fn run_one_handle<F: Future>(fut: F) -> Result<F::Output> {
    let ex = HandleExecutor::new().map_err(Error::HandleExecutor)?;
    ex.run_until(fut).map_err(Error::HandleExecutor)
}

/// Creates an Executor that runs one future to completion.
///
///  # Example
///
///    ```
///    #[cfg(unix)]
///    {
///        use cros_async::run_one;
///
///        let fut = async { 55 };
///        assert_eq!(55, run_one(fut).unwrap());
///    }
///    ```
pub fn run_one<F: Future>(fut: F) -> Result<F::Output> {
    run_one_handle(fut)
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            HandleExecutor(e) => e.into(),
            Timer(e) => e.into(),
            TimerAsync(e) => e.into(),
        }
    }
}

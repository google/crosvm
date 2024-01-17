// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_types;
mod error;
pub mod event;
pub mod executor;
pub mod fd_executor;
pub mod poll_source;
mod timer;
pub mod uring_executor;
pub mod uring_source;

pub use error::AsyncErrorSys;
pub use executor::ExecutorKindSys;
pub use poll_source::Error as PollSourceError;
pub use poll_source::PollSource;
pub use uring_source::UringSource;

use crate::Error;

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            Io(e) => e,
            URingExecutor(e) => e.into(),
            PollSource(e) => e.into(),
            Timer(e) => e.into(),
            TimerAsync(e) => e.into(),
        }
    }
}

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_types;
mod error;
pub mod event;
pub mod executor;
pub mod handle_executor;
pub mod handle_source;
mod io_completion_port;
pub mod overlapped_source;
mod timer;
pub mod wait_for_handle;

pub use error::AsyncErrorSys;
pub use handle_executor::HandleReactor;
pub use handle_source::HandleSource;
pub use handle_source::HandleWrapper;
pub use overlapped_source::OverlappedSource;
pub(crate) use wait_for_handle::WaitForHandle;

use crate::Error;

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            HandleExecutor(e) => e.into(),
            Io(e) => e,
            Timer(e) => e.into(),
            TimerAsync(e) => e.into(),
        }
    }
}

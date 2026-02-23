// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod async_types;
mod error;
pub mod event;
pub mod executor;
pub mod kqueue_executor;
pub mod kqueue_source;
mod timer;
#[cfg(feature = "tokio")]
pub mod tokio_source;

pub use error::AsyncErrorSys;
pub use executor::ExecutorKindSys;
pub(crate) use kqueue_executor::KqueueReactor;
pub use kqueue_source::Error as KqueueSourceError;
pub use kqueue_source::KqueueSource;

use crate::Error;

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            EventAsync(e) => e.into(),
            Io(e) => e,
            KqueueSource(e) => e.into(),
            Timer(e) => e.into(),
            TimerAsync(e) => e.into(),
        }
    }
}

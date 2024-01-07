// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

#[remain::sorted]
#[derive(Debug, thiserror::Error)]
pub enum AsyncErrorSys {
    #[error("Poll source error: {0}")]
    Poll(#[from] super::poll_source::Error),
    #[cfg(feature = "tokio")]
    #[error("Tokio source error: {0}")]
    Tokio(#[from] super::tokio_source::Error),
    #[error("Uring source error: {0}")]
    Uring(#[from] super::uring_executor::Error),
}

impl From<AsyncErrorSys> for io::Error {
    fn from(err: AsyncErrorSys) -> Self {
        match err {
            AsyncErrorSys::Poll(e) => e.into(),
            #[cfg(feature = "tokio")]
            AsyncErrorSys::Tokio(e) => e.into(),
            AsyncErrorSys::Uring(e) => e.into(),
        }
    }
}

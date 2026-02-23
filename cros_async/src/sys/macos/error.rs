// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

#[remain::sorted]
#[derive(Debug, thiserror::Error)]
pub enum AsyncErrorSys {
    #[error("Kqueue source error: {0}")]
    Kqueue(#[from] super::kqueue_source::Error),
    #[cfg(feature = "tokio")]
    #[error("Tokio source error: {0}")]
    Tokio(#[from] super::tokio_source::Error),
}

impl From<AsyncErrorSys> for io::Error {
    fn from(err: AsyncErrorSys) -> Self {
        match err {
            AsyncErrorSys::Kqueue(e) => e.into(),
            #[cfg(feature = "tokio")]
            AsyncErrorSys::Tokio(e) => e.into(),
        }
    }
}

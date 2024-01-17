// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

#[remain::sorted]
#[derive(Debug, thiserror::Error)]
pub enum AsyncErrorSys {
    #[error("An error with a handle executor: {0}")]
    HandleExecutor(#[from] super::handle_executor::Error),
    #[error("An error with a handle source: {0}")]
    HandleSource(#[from] super::handle_source::Error),
    #[error("An error with a handle source: {0}")]
    OverlappedSource(#[from] super::overlapped_source::Error),
}

impl From<AsyncErrorSys> for io::Error {
    fn from(err: AsyncErrorSys) -> Self {
        match err {
            AsyncErrorSys::HandleExecutor(e) => e.into(),
            AsyncErrorSys::HandleSource(e) => e.into(),
            AsyncErrorSys::OverlappedSource(e) => e.into(),
        }
    }
}

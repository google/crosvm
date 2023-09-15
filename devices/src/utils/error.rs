// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Error as SysError;
use remain::sorted;
use thiserror::Error;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create event: {0}")]
    CreateEvent(SysError),
    #[error("failed to create poll context: {0}")]
    CreateWaitContext(SysError),
    #[error("event loop already failed due to previous errors")]
    EventLoopAlreadyFailed,
    #[error("attempted to resume polling descriptor without handler")]
    EventLoopMissingHandler,
    #[error("failed to read event: {0}")]
    ReadEvent(SysError),
    #[error("failed to start thread: {0}")]
    StartThread(std::io::Error),
    #[error("failed to add fd to poll context: {0}")]
    WaitContextAddDescriptor(SysError),
    #[error("failed to delete fd from poll context: {0}")]
    WaitContextDeleteDescriptor(SysError),
    #[error("failed to write event: {0}")]
    WriteEvent(SysError),
}

pub type Result<T> = std::result::Result<T, Error>;

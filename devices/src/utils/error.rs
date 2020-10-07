// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Error as SysError;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum Error {
    EventLoopAlreadyFailed,
    CreateEvent(SysError),
    ReadEvent(SysError),
    WriteEvent(SysError),
    CreateWaitContext(SysError),
    WaitContextAddDescriptor(SysError),
    WaitContextDeleteDescriptor(SysError),
    StartThread(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            EventLoopAlreadyFailed => write!(f, "event loop already failed due to previous errors"),
            CreateEvent(e) => write!(f, "failed to create event: {}", e),
            ReadEvent(e) => write!(f, "failed to read event: {}", e),
            WriteEvent(e) => write!(f, "failed to write event: {}", e),
            CreateWaitContext(e) => write!(f, "failed to create poll context: {}", e),
            WaitContextAddDescriptor(e) => write!(f, "failed to add fd to poll context: {}", e),
            WaitContextDeleteDescriptor(e) => {
                write!(f, "failed to delete fd from poll context: {}", e)
            }
            StartThread(e) => write!(f, "failed to start thread: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

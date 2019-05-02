// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use sys_util::Error as SysError;

#[derive(Debug)]
pub enum Error {
    EventLoopAlreadyFailed,
    CreateEventFd(SysError),
    ReadEventFd(SysError),
    WriteEventFd(SysError),
    CreatePollContext(SysError),
    PollContextAddFd(SysError),
    PollContextDeleteFd(SysError),
    StartThread(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            EventLoopAlreadyFailed => write!(f, "event loop already failed due to previous errors"),
            CreateEventFd(e) => write!(f, "failed to create event fd: {}", e),
            ReadEventFd(e) => write!(f, "failed to read event fd: {}", e),
            WriteEventFd(e) => write!(f, "failed to write event fd: {}", e),
            CreatePollContext(e) => write!(f, "failed to create poll context: {}", e),
            PollContextAddFd(e) => write!(f, "failed to add fd to poll context: {}", e),
            PollContextDeleteFd(e) => write!(f, "failed to delete fd from poll context: {}", e),
            StartThread(e) => write!(f, "failed to start thread: {}", e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

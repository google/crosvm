// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::io;
use std::result;

use libc::__errno_location;

/// An error number, retrieved from errno (man 3 errno), set by a libc
/// function that returned an error.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Error(i32);
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Constructs a new error with the given errno.
    pub fn new(e: i32) -> Error {
        Error(e)
    }

    /// Constructs an error from the current errno.
    ///
    /// The result of this only has any meaning just after a libc call that returned a value
    /// indicating errno was set.
    pub fn last() -> Error {
        Error(unsafe { *__errno_location() })
    }

    /// Gets the errno for this error
    pub fn errno(self) -> i32 {
        self.0
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::new(e.raw_os_error().unwrap_or_default())
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        io::Error::from_raw_os_error(self.0).fmt(f)
    }
}

/// Returns the last errno as a Result that is always an error.
pub fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

/// Sets errno to given error code.
/// Only defined when we compile tests as normal code does not
/// normally need set errno.
#[cfg(test)]
pub fn set_errno(e: i32) {
    unsafe {
        *__errno_location() = e;
    }
}

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::io;
use std::result;

use serde::{Deserialize, Serialize};

/// An error number, retrieved from errno (man 3 errno), set by a libc
/// function that returned an error.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[serde(transparent)]
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
        Error(io::Error::last_os_error().raw_os_error().unwrap())
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

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::from_raw_os_error(e.0)
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Into::<io::Error>::into(*self).fmt(f)
    }
}

/// Returns the last errno as a Result that is always an error.
pub fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

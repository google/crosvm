// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::result;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// A system error
/// In Unix systems, retrieved from errno (man 3 errno), set by a libc
/// function that returned an error.
/// On Windows, retrieved from GetLastError, set by a Windows function
/// that returned an error
#[derive(Error, Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct Error(i32);
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Constructs a new error with the given error number.
    pub fn new<T: TryInto<i32>>(e: T) -> Error {
        // A value outside the bounds of an i32 will never be a valid
        // errno/GetLastError
        Error(e.try_into().unwrap_or_default())
    }

    /// Constructs an Error from the most recent system error.
    ///
    /// The result of this only has any meaning just after a libc/Windows call that returned
    /// a value indicating errno was set.
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
        Error(e.raw_os_error().unwrap_or_default())
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::from_raw_os_error(e.0)
    }
}

impl From<Error> for Box<dyn std::error::Error + Send> {
    fn from(e: Error) -> Self {
        Box::new(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Into::<io::Error>::into(*self).fmt(f)
    }
}

/// Returns the last errno as a Result that is always an error.
pub fn errno_result<T>() -> Result<T> {
    Err(Error::last())
}

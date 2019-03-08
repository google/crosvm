// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::fmt;

use crate::bindings;

/// Error type for libusb.
pub enum Error {
    Success(i32),
    IO,
    InvalidParam,
    Access,
    NoDevice,
    NotFound,
    Busy,
    Timeout,
    Overflow,
    Pipe,
    Interrupted,
    NoMem,
    NotSupported,
    Other,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Success(_v) => write!(f, "Success (no error)"),
            Error::IO => write!(f, "Input/output error"),
            Error::InvalidParam => write!(f, "Invalid parameter"),
            Error::Access => write!(f, "Access denied (insufficient permissions)"),
            Error::NoDevice => write!(f, "No such device (it may have been disconnected)"),
            Error::NotFound => write!(f, "Entity not found"),
            Error::Busy => write!(f, "Resource busy"),
            Error::Timeout => write!(f, "Operation timed out"),
            Error::Overflow => write!(f, "Overflow"),
            Error::Pipe => write!(f, "Pipe error"),
            Error::Interrupted => write!(f, "System call interrupted (perhaps due to signal)"),
            Error::NoMem => write!(f, "Insufficient memory"),
            Error::NotSupported => write!(
                f,
                "Operation not supported or unimplemented on this platform"
            ),
            Error::Other => write!(f, "Other error"),
        }
    }
}

impl From<bindings::libusb_error> for Error {
    fn from(e: bindings::libusb_error) -> Self {
        match e {
            bindings::LIBUSB_ERROR_IO => Error::IO,
            bindings::LIBUSB_ERROR_INVALID_PARAM => Error::InvalidParam,
            bindings::LIBUSB_ERROR_ACCESS => Error::Access,
            bindings::LIBUSB_ERROR_NO_DEVICE => Error::NoDevice,
            bindings::LIBUSB_ERROR_NOT_FOUND => Error::NotFound,
            bindings::LIBUSB_ERROR_BUSY => Error::Busy,
            bindings::LIBUSB_ERROR_TIMEOUT => Error::Timeout,
            bindings::LIBUSB_ERROR_OVERFLOW => Error::Overflow,
            bindings::LIBUSB_ERROR_PIPE => Error::Pipe,
            bindings::LIBUSB_ERROR_INTERRUPTED => Error::Interrupted,
            bindings::LIBUSB_ERROR_NO_MEM => Error::NoMem,
            bindings::LIBUSB_ERROR_NOT_SUPPORTED => Error::NotSupported,
            bindings::LIBUSB_ERROR_OTHER => Error::Other,
            // All possible errors are defined above, other values mean success,
            // see libusb_get_device_list for example.
            _ => Error::Success(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[macro_export]
macro_rules! try_libusb {
    ($x:expr) => {
        match Error::from($x as i32) {
            Error::Success(e) => e,
            err => return Err(err),
        }
    };
}

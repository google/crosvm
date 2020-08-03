// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::IoctlNr;
use remain::sorted;
use std::fmt::{self, Display};
use std::io;
use std::num;

#[sorted]
#[derive(Debug)]
pub enum Error {
    DescriptorParse,
    DescriptorRead(io::Error),
    FdCloneFailed(io::Error),
    InvalidActualLength(num::TryFromIntError),
    InvalidBufferLength(num::TryFromIntError),
    IoctlFailed(IoctlNr, base::Error),
    NoDevice,
    NoSuchDescriptor,
    RcGetMutFailed,
    RcUnwrapFailed,
    TransferAlreadyCompleted,
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            DescriptorParse => write!(f, "parsing descriptors failed"),
            DescriptorRead(e) => write!(f, "reading descriptors from device failed: {}", e),
            FdCloneFailed(e) => write!(f, "File::try_clone() failed: {}", e),
            InvalidActualLength(e) => write!(f, "invalid actual_length in URB: {}", e),
            InvalidBufferLength(e) => write!(f, "invalid transfer buffer length: {}", e),
            IoctlFailed(nr, e) => write!(f, "USB ioctl 0x{:x} failed: {}", nr, e),
            NoDevice => write!(f, "Device has been removed"),
            NoSuchDescriptor => write!(f, "Requested descriptor not found"),
            RcGetMutFailed => write!(f, "Rc::get_mut failed"),
            RcUnwrapFailed => write!(f, "Rc::try_unwrap failed"),
            TransferAlreadyCompleted => write!(f, "attempted to cancel already-completed transfer"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

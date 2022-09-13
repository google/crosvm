// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::num;

use base::IoctlNr;
use remain::sorted;
use thiserror::Error;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("parsing descriptors failed")]
    DescriptorParse,
    #[error("reading descriptors from device failed: {0}")]
    DescriptorRead(io::Error),
    #[error("File::try_clone() failed: {0}")]
    FdCloneFailed(io::Error),
    #[error("invalid actual_length in URB: {0}")]
    InvalidActualLength(num::TryFromIntError),
    #[error("invalid transfer buffer length: {0}")]
    InvalidBufferLength(num::TryFromIntError),
    #[error("USB ioctl 0x{0:x} failed: {1}")]
    IoctlFailed(IoctlNr, base::Error),
    #[error("Device has been removed")]
    NoDevice,
    #[error("Requested descriptor not found")]
    NoSuchDescriptor,
    #[error("Rc::get_mut failed")]
    RcGetMutFailed,
    #[error("Rc::try_unwrap failed")]
    RcUnwrapFailed,
    #[error("attempted to cancel already-completed transfer")]
    TransferAlreadyCompleted,
}

pub type Result<T> = std::result::Result<T, Error>;

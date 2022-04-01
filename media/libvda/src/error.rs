// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Errors that can happen in LibVDA.

use std::error;
use std::fmt::{self, Display};

use super::format;
use crate::decode;
use crate::encode;

#[derive(Debug)]
pub enum Error {
    // Encode session error. The error code provided is specific
    // to the implementation type (`VeaImplType`).
    EncodeSessionFailure(i32),
    EncodeSessionInitFailure(encode::Config),
    GetCapabilitiesFailure,
    InstanceInitFailure,
    InvalidCapabilities(String),
    LibVdaFailure(decode::Response),
    ReadEventFailure(std::io::Error),
    SessionIdAlreadyUsed(u32),
    SessionInitFailure(format::Profile),
    SessionNotFound(u32),
    UnknownPixelFormat(u32),
    UnknownProfile(i32),
}

pub type Result<T> = std::result::Result<T, Error>;

impl error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            EncodeSessionFailure(e) => write!(f, "encode session error: {}", e),
            EncodeSessionInitFailure(c) => {
                write!(f, "failed to initialize encode session with config {:?}", c)
            }
            GetCapabilitiesFailure => write!(f, "failed to get capabilities"),
            InstanceInitFailure => write!(f, "failed to initialize VDA instance"),
            InvalidCapabilities(e) => write!(f, "obtained capabilities are invalid: {}", e),
            LibVdaFailure(e) => write!(f, "error happened in libvda: {}", e),
            ReadEventFailure(e) => write!(f, "failed to read event: {}", e),
            SessionInitFailure(p) => write!(f, "failed to initialize decode session with {:?}", p),
            SessionIdAlreadyUsed(id) => write!(f, "session_id {} is already used", id),
            SessionNotFound(id) => write!(f, "no session has session_id {}", id),
            UnknownPixelFormat(p) => write!(f, "unknown pixel format: {}", p),
            UnknownProfile(p) => write!(f, "unknown profile: {}", p),
        }
    }
}

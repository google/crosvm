// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::fmt;
use std::fmt::Debug;

use libc::iovec;

use crate::iobuf::PlatformIoBuf;

/// Cross platform binary compatible iovec. See [`crate::IoBufMut`] for documentation.
pub type IoBuf = iovec;

impl PlatformIoBuf for IoBuf {
    #[inline]
    fn new(ptr: *mut u8, len: usize) -> Self {
        iovec {
            iov_base: ptr as *mut c_void,
            iov_len: len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.iov_len
    }

    #[inline]
    fn ptr(&self) -> *mut u8 {
        self.iov_base as *mut u8
    }

    #[inline]
    fn set_len(&mut self, len: usize) {
        self.iov_len = len;
    }

    #[inline]
    fn set_ptr(&mut self, ptr: *mut u8) {
        self.iov_base = ptr as *mut c_void;
    }
}

pub(crate) struct DebugIoBuf(pub(crate) iovec);
impl Debug for DebugIoBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("iovec")
            .field("iov_base", &self.0.iov_base)
            .field("iov_len", &self.0.iov_len)
            .finish()
    }
}

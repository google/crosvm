// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;

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

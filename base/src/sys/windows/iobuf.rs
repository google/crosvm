// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use winapi::shared::ws2def::WSABUF;

use crate::iobuf::PlatformIoBuf;

/// Cross platform binary compatible iovec. See [`crate::IoBufMut`] for documentation.
pub type IoBuf = WSABUF;

impl PlatformIoBuf for IoBuf {
    #[inline]
    fn new(ptr: *mut u8, len: usize) -> Self {
        WSABUF {
            buf: ptr as *mut i8,
            len: len.try_into().unwrap(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    fn ptr(&self) -> *mut u8 {
        self.buf as *mut u8
    }

    #[inline]
    fn set_len(&mut self, len: usize) {
        self.len = len.try_into().unwrap();
    }

    #[inline]
    fn set_ptr(&mut self, ptr: *mut u8) {
        self.buf = ptr as *mut i8;
    }
}

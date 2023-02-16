// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::slice;

use winapi::shared::ws2def::WSABUF;

/// Cross platform binary compatible iovec.
pub type IoBuf = WSABUF;

/// Cross platform stub to create a platform specific IoBuf.
pub fn create_iobuf(addr: *mut u8, len: usize) -> IoBuf {
    WSABUF {
        buf: addr as *mut i8,
        len: len as u32,
    }
}

/// This type is essentialy `std::io::IoSliceMut`, and guaranteed to be ABI-compatible with
/// `WSABUF`; however, it does NOT automatically deref to `&mut [u8]`, which is critical
/// because it can point to guest memory. (Guest memory is implicitly mutably borrowed by the
/// guest, so another mutable borrow would violate Rust assumptions about references.)
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct IoBufMut<'a> {
    buf: WSABUF,
    phantom: PhantomData<&'a mut [u8]>,
}

impl<'a> IoBufMut<'a> {
    pub fn new(buf: &mut [u8]) -> IoBufMut<'a> {
        // Safe because buf's memory is of the supplied length, and
        // guaranteed to exist for the lifetime of the returned value.
        unsafe { Self::from_raw_parts(buf.as_mut_ptr(), buf.len()) }
    }

    /// Creates a `IoBufMut` from a pointer and a length.
    ///
    /// # Safety
    ///
    /// In order to use this method safely, `addr` must be valid for reads and writes of `len` bytes
    /// and should live for the entire duration of lifetime `'a`.
    pub unsafe fn from_raw_parts(addr: *mut u8, len: usize) -> IoBufMut<'a> {
        IoBufMut {
            buf: WSABUF {
                buf: addr as *mut i8,
                len: len as u32,
            },
            phantom: PhantomData,
        }
    }

    /// Creates a `IoBufMut` from an IoBuf.
    ///
    /// # Safety
    ///
    /// In order to use this method safely, `iobuf` must be valid for reads and writes through its
    /// length and should live for the entire duration of lifetime `'a`.
    pub unsafe fn from_iobuf(iobuf: IoBuf) -> IoBufMut<'a> {
        IoBufMut {
            buf: iobuf,
            phantom: PhantomData,
        }
    }

    /// Advance the internal position of the buffer.
    ///
    /// Panics if `count > self.len()`.
    pub fn advance(&mut self, _count: usize) {
        unimplemented!()
    }

    /// Shorten the length of the buffer.
    ///
    /// Has no effect if `len > self.len()`.
    pub fn truncate(&mut self, _len: usize) {
        unimplemented!()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len as usize
    }

    /// Gets a const pointer to this slice's memory.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.buf as *const u8
    }

    /// Gets a mutable pointer to this slice's memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.buf.buf as *mut u8
    }

    /// Converts a slice of `IoBufMut`s into a slice of `iovec`s.
    #[inline]
    pub fn as_iobufs<'slice>(iovs: &'slice [IoBufMut<'_>]) -> &'slice [IoBuf] {
        // Safe because `IoBufMut` is ABI-compatible with `WSABUF`.
        unsafe { slice::from_raw_parts(iovs.as_ptr() as *const WSABUF, iovs.len()) }
    }
}

impl<'a> AsRef<WSABUF> for IoBufMut<'a> {
    fn as_ref(&self) -> &WSABUF {
        &self.buf
    }
}

impl<'a> AsMut<WSABUF> for IoBufMut<'a> {
    fn as_mut(&mut self) -> &mut WSABUF {
        &mut self.buf
    }
}

struct DebugWSABUF(WSABUF);
impl Debug for DebugWSABUF {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("WSABUF")
            .field("buf", &self.0.buf)
            .field("len", &self.0.len)
            .finish()
    }
}

impl<'a> Debug for IoBufMut<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IoBufMut")
            .field("buf", &DebugWSABUF(self.buf))
            .field("phantom", &self.phantom)
            .finish()
    }
}

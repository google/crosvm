// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::slice;

use libc::iovec;

/// Cross platform binary compatible iovec.
pub type IoBuf = iovec;

/// Cross platform stub to create a platform specific IoBuf.
pub fn create_iobuf(addr: *mut u8, len: usize) -> IoBuf {
    iovec {
        iov_base: addr as *mut c_void,
        iov_len: len,
    }
}

/// This type is essentialy `std::io::IoSliceMut`, and guaranteed to be ABI-compatible with
/// `libc::iovec`; however, it does NOT automatically deref to `&mut [u8]`, which is critical
/// because it can point to guest memory. (Guest memory is implicitly mutably borrowed by the
/// guest, so another mutable borrow would violate Rust assumptions about references.)
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct IoBufMut<'a> {
    iov: iovec,
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
            iov: iovec {
                iov_base: addr as *mut c_void,
                iov_len: len,
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
            iov: iobuf,
            phantom: PhantomData,
        }
    }

    /// Advance the internal position of the buffer.
    ///
    /// Panics if `count > self.len()`.
    pub fn advance(&mut self, count: usize) {
        assert!(count <= self.len());

        self.iov.iov_len -= count;
        // Safe because we've checked that `count <= self.len()` so both the starting and resulting
        // pointer are within the bounds of the allocation.
        self.iov.iov_base = unsafe { self.iov.iov_base.add(count) };
    }

    /// Shorten the length of the buffer.
    ///
    /// Has no effect if `len > self.len()`.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.iov.iov_len = len;
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.iov.iov_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.iov.iov_len == 0
    }

    /// Gets a const pointer to this slice's memory.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.iov.iov_base as *const u8
    }

    /// Gets a mutable pointer to this slice's memory.
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.iov.iov_base as *mut u8
    }

    /// Converts a slice of `IoBufMut`s into a slice of `iovec`s.
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    pub fn as_iobufs<'slice>(iovs: &'slice [IoBufMut<'_>]) -> &'slice [iovec] {
        // Safe because `IoBufMut` is ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(iovs.as_ptr() as *const libc::iovec, iovs.len()) }
    }
}

impl<'a> AsRef<libc::iovec> for IoBufMut<'a> {
    fn as_ref(&self) -> &libc::iovec {
        &self.iov
    }
}

impl<'a> AsMut<libc::iovec> for IoBufMut<'a> {
    fn as_mut(&mut self) -> &mut libc::iovec {
        &mut self.iov
    }
}

// It's safe to implement Send + Sync for this type for the same reason that `std::io::IoSliceMut`
// is Send + Sync. Internally, it contains a pointer and a length. The integer length is safely Send
// + Sync.  There's nothing wrong with sending a pointer between threads and de-referencing the
// pointer requires an unsafe block anyway. See also https://github.com/rust-lang/rust/pull/70342.
unsafe impl<'a> Send for IoBufMut<'a> {}
unsafe impl<'a> Sync for IoBufMut<'a> {}

struct DebugIovec(iovec);
impl Debug for DebugIovec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("iovec")
            .field("iov_base", &self.0.iov_base)
            .field("iov_len", &self.0.iov_len)
            .finish()
    }
}

impl<'a> Debug for IoBufMut<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IoBufMut")
            .field("iov", &DebugIovec(self.iov))
            .field("phantom", &self.phantom)
            .finish()
    }
}

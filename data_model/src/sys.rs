use std::ffi::c_void;
use std::fmt::{self, Debug};
use std::marker::PhantomData;
use std::slice;

use libc::iovec;

/// This type is essentialy `std::io::IoSliceMut`, and guaranteed to be ABI-compatible with
/// `libc::iovec`; however, it does NOT automatically deref to `&mut [u8]`, which is critical
/// because it can point to guest memory. (Guest memory is implicitly mutably borrowed by the
/// guest, so another mutable borrow would violate Rust assumptions about references.)
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct IoSliceMut<'a> {
    iov: iovec,
    phantom: PhantomData<&'a mut [u8]>,
}

impl<'a> IoSliceMut<'a> {
    pub fn new(buf: &mut [u8]) -> IoSliceMut<'a> {
        // Safe because buf's memory is of the supplied length, and
        // guaranteed to exist for the lifetime of the returned value.
        unsafe { Self::from_raw_parts(buf.as_mut_ptr(), buf.len()) }
    }

    /// Creates a `IoSliceMut` from a pointer and a length.
    ///
    /// # Safety
    ///
    /// In order to use this method safely, `addr` must be valid for reads and writes of `len` bytes
    /// and should live for the entire duration of lifetime `'a`.
    pub unsafe fn from_raw_parts(addr: *mut u8, len: usize) -> IoSliceMut<'a> {
        IoSliceMut {
            iov: iovec {
                iov_base: addr as *mut c_void,
                iov_len: len,
            },
            phantom: PhantomData,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.iov.iov_len as usize
    }

    #[inline]
    pub fn as_iobuf(&self) -> libc::iovec {
        self.iov
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

    /// Converts a slice of `IoSliceMut`s into a slice of `iovec`s.
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    pub fn as_iobufs<'slice>(iovs: &'slice [IoSliceMut<'_>]) -> &'slice [iovec] {
        // Safe because `IoSliceMut` is ABI-compatible with `iovec`.
        unsafe { slice::from_raw_parts(iovs.as_ptr() as *const libc::iovec, iovs.len()) }
    }
}

struct DebugIovec(iovec);
impl Debug for DebugIovec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("iovec")
            .field("iov_base", &self.0.iov_base)
            .field("iov_len", &self.0.iov_len)
            .finish()
    }
}

impl<'a> Debug for IoSliceMut<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IoSliceMut")
            .field("iov", &DebugIovec(self.iov))
            .field("phantom", &self.phantom)
            .finish()
    }
}

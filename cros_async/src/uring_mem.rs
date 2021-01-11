// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::io::IoSliceMut;
use std::marker::PhantomData;

#[derive(Debug)]
pub enum Error {
    /// Invalid offset or length given for an iovec in backing memory.
    InvalidOffset(u64, usize),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            InvalidOffset(base, len) => write!(
                f,
                "Invalid offset/len for getting a slice from {} with len {}.",
                base, len
            ),
        }
    }
}
impl std::error::Error for Error {}

/// Used to index subslices of backing memory. Like an iovec, but relative to the start of the
/// memory region instead of an absolute pointer.
/// The backing memory referenced by the region can be an array, an mmapped file, or guest memory.
/// The offset is a u64 to allow having file or guest offsets >4GB when run on a 32bit host.
#[derive(Copy, Clone, Debug)]
pub struct MemRegion {
    pub offset: u64,
    pub len: usize,
}

/// An iovec that borrows the backing memory it points to.
/// This ties the lifetime of the iovec to the memory, ensuring it is still valid when it is used.
#[repr(transparent)]
pub struct BorrowedIoVec<'a> {
    iovec: libc::iovec,
    backing_memory: PhantomData<&'a ()>,
}

impl<'a> BorrowedIoVec<'a> {
    /// Creates a BorrowedIoVec from an existing IoSlice.
    pub fn new(ioslice: IoSliceMut<'a>) -> BorrowedIoVec<'a> {
        Self {
            // Safe because IoSliceMut guarantees ABI compatibility with iovec.
            iovec: unsafe { std::mem::transmute(ioslice) },
            backing_memory: PhantomData,
        }
    }

    /// Creates a BorrowedIoVec from a pointer and length.
    /// # Safety
    /// The caller must guarantee that memory from `ptr` to `ptr` + `len` is valid for the duration
    /// of lifetime `'a`.
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> BorrowedIoVec<'a> {
        Self {
            iovec: libc::iovec {
                iov_base: ptr as *mut _,
                iov_len: len,
            },
            backing_memory: PhantomData,
        }
    }

    ///  Access the inner iovec for this borrowed iovec.
    pub fn iovec(&self) -> libc::iovec {
        self.iovec
    }
}

/// Trait for memory that can yeild both iovecs in to the backing memory.
/// Must be OK to modify the backing memory without owning a mut able reference. For example,
/// this is safe for GuestMemory and VolatileSlices in crosvm as those types guarantee they are
/// dealt with as volatile.
pub unsafe trait BackingMemory {
    /// Returns an iovec pointing to the backing memory. This is most commonly unsafe. To implement
    /// this safely the implementor must guarantee that the backing memory can be modified out of
    /// band without affecting safety guarantees.
    fn get_iovec(&self, mem_range: MemRegion) -> Result<BorrowedIoVec>;
}

/// Wrapper to be used for passing a Vec in as backing memory for asynchronous operations.  The
/// wrapper owns a Vec according to the borrow checker. It is loaning this vec out to the kernel(or
/// other modifiers) through the `BackingMemory` trait. This allows multiple modifiers of the array
/// in the `Vec` while this struct is alive. The data in the Vec is loaned to the kernel not the
/// data structure itself, the length, capacity, and pointer to memory cannot be modified.
/// To ensure that those operations can be done safely, no access is allowed to the `Vec`'s memory
/// starting at the time that `VecIoWrapper` is constructed until the time it is turned back in to a
/// `Vec` using `to_inner`. The returned `Vec` is guaranteed to be valid as any combination of bits
/// in a `Vec` of `u8` is valid.
pub(crate) struct VecIoWrapper {
    inner: Box<[u8]>,
}

impl From<Vec<u8>> for VecIoWrapper {
    fn from(vec: Vec<u8>) -> Self {
        VecIoWrapper { inner: vec.into() }
    }
}

impl Into<Vec<u8>> for VecIoWrapper {
    fn into(self) -> Vec<u8> {
        self.inner.into()
    }
}

impl VecIoWrapper {
    /// Get the length of the Vec that is wrapped.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    // Check that the offsets are all valid in the backing vec.
    fn check_addrs(&self, mem_range: &MemRegion) -> Result<()> {
        let end = mem_range
            .offset
            .checked_add(mem_range.len as u64)
            .ok_or(Error::InvalidOffset(mem_range.offset, mem_range.len))?;
        if end > self.inner.len() as u64 {
            return Err(Error::InvalidOffset(mem_range.offset, mem_range.len));
        }
        Ok(())
    }
}

// Safe to implement BackingMemory as the vec is only accessible inside the wrapper and these iovecs
// are the only thing allowed to modify it.  Nothing else can get a reference to the vec until all
// iovecs are dropped because they borrow Self.  Nothing can borrow the owned inner vec until self
// is consumed by `into`, which can't happen if there are outstanding mut borrows.
unsafe impl BackingMemory for VecIoWrapper {
    fn get_iovec(&self, mem_range: MemRegion) -> Result<BorrowedIoVec<'_>> {
        self.check_addrs(&mem_range)?;
        // Safe because the mem_range range is valid in the backing memory as checked above.
        unsafe {
            Ok(BorrowedIoVec::from_raw_parts(
                self.inner.as_ptr().add(mem_range.offset as usize) as *mut _,
                mem_range.len,
            ))
        }
    }
}

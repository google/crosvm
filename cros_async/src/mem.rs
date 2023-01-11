// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::VolatileSlice;
use remain::sorted;
use thiserror::Error as ThisError;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Invalid offset or length given for an iovec in backing memory.
    #[error("Invalid offset/len for getting a slice from {0} with len {1}.")]
    InvalidOffset(u64, usize),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Used to index subslices of backing memory. Like an iovec, but relative to the start of the
/// backing memory instead of an absolute pointer.
/// The backing memory referenced by the region can be an array, an mmapped file, or guest memory.
/// The offset is a u64 to allow having file or guest offsets >4GB when run on a 32bit host.
#[derive(Copy, Clone, Debug)]
pub struct MemRegion {
    pub offset: u64,
    pub len: usize,
}

/// Trait for memory that can yield both iovecs in to the backing memory.
/// # Safety
/// Must be OK to modify the backing memory without owning a mut able reference. For example,
/// this is safe for GuestMemory and VolatileSlices in crosvm as those types guarantee they are
/// dealt with as volatile.
pub unsafe trait BackingMemory {
    /// Returns VolatileSlice pointing to the backing memory. This is most commonly unsafe.
    /// To implement this safely the implementor must guarantee that the backing memory can be
    /// modified out of band without affecting safety guarantees.
    fn get_volatile_slice(&self, mem_range: MemRegion) -> Result<VolatileSlice>;
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

impl From<VecIoWrapper> for Vec<u8> {
    fn from(v: VecIoWrapper) -> Vec<u8> {
        v.inner.into()
    }
}

impl VecIoWrapper {
    /// Get the length of the Vec that is wrapped.
    #[cfg_attr(windows, allow(dead_code))]
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
    fn get_volatile_slice(&self, mem_range: MemRegion) -> Result<VolatileSlice<'_>> {
        self.check_addrs(&mem_range)?;
        // Safe because the mem_range range is valid in the backing memory as checked above.
        unsafe {
            Ok(VolatileSlice::from_raw_parts(
                self.inner.as_ptr().add(mem_range.offset as usize) as *mut _,
                mem_range.len,
            ))
        }
    }
}

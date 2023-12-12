// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Types for volatile access to memory.
//!
//! Two of the core rules for safe rust is no data races and no aliased mutable references.
//! `VolatileSlice`, along with types that produce it which implement
//! `VolatileMemory`, allow us to sidestep that rule by wrapping pointers that absolutely have to be
//! accessed volatile. Some systems really do need to operate on shared memory and can't have the
//! compiler reordering or eliding access because it has no visibility into what other systems are
//! doing with that hunk of memory.
//!
//! For the purposes of maintaining safety, volatile memory has some rules of its own:
//! 1. No references or slices to volatile memory (`&` or `&mut`).
//! 2. Access should always been done with a volatile read or write.
//! The First rule is because having references of any kind to memory considered volatile would
//! violate pointer aliasing. The second is because unvolatile accesses are inherently undefined if
//! done concurrently without synchronization. With volatile access we know that the compiler has
//! not reordered or elided the access.

use std::cmp::min;
use std::mem::size_of;
use std::ptr::copy;
use std::ptr::read_volatile;
use std::ptr::write_bytes;
use std::ptr::write_volatile;
use std::result;
use std::slice;
use std::usize;

use remain::sorted;
use thiserror::Error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::Ref;

use crate::IoBufMut;

#[sorted]
#[derive(Error, Eq, PartialEq, Debug)]
pub enum VolatileMemoryError {
    /// `addr` is out of bounds of the volatile memory slice.
    #[error("address 0x{addr:x} is out of bounds")]
    OutOfBounds { addr: usize },
    /// Taking a slice at `base` with `offset` would overflow `usize`.
    #[error("address 0x{base:x} offset by 0x{offset:x} would overflow")]
    Overflow { base: usize, offset: usize },
}

pub type VolatileMemoryResult<T> = result::Result<T, VolatileMemoryError>;

use crate::VolatileMemoryError as Error;
type Result<T> = VolatileMemoryResult<T>;

/// Trait for types that support raw volatile access to their data.
pub trait VolatileMemory {
    /// Gets a slice of memory at `offset` that is `count` bytes in length and supports volatile
    /// access.
    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice>;
}

/// A slice of raw memory that supports volatile access. Like `std::io::IoSliceMut`, this type is
/// guaranteed to be ABI-compatible with `libc::iovec` but unlike `IoSliceMut`, it doesn't
/// automatically deref to `&mut [u8]`.
#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct VolatileSlice<'a>(IoBufMut<'a>);

impl<'a> VolatileSlice<'a> {
    /// Creates a slice of raw memory that must support volatile access.
    pub fn new(buf: &mut [u8]) -> VolatileSlice {
        VolatileSlice(IoBufMut::new(buf))
    }

    /// Creates a `VolatileSlice` from a pointer and a length.
    ///
    /// # Safety
    ///
    /// In order to use this method safely, `addr` must be valid for reads and writes of `len` bytes
    /// and should live for the entire duration of lifetime `'a`.
    pub unsafe fn from_raw_parts(addr: *mut u8, len: usize) -> VolatileSlice<'a> {
        VolatileSlice(IoBufMut::from_raw_parts(addr, len))
    }

    /// Gets a const pointer to this slice's memory.
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    /// Gets a mutable pointer to this slice's memory.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// Gets the size of this slice.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Advance the starting position of this slice.
    ///
    /// Panics if `count > self.size()`.
    pub fn advance(&mut self, count: usize) {
        self.0.advance(count)
    }

    /// Shorten the length of the slice.
    ///
    /// Has no effect if `len > self.size()`.
    pub fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }

    /// Returns this `VolatileSlice` as an `IoBufMut`.
    pub fn as_iobuf(&self) -> &IoBufMut {
        &self.0
    }

    /// Converts a slice of `VolatileSlice`s into a slice of `IoBufMut`s
    #[allow(clippy::wrong_self_convention)]
    pub fn as_iobufs<'mem, 'slice>(
        iovs: &'slice [VolatileSlice<'mem>],
    ) -> &'slice [IoBufMut<'mem>] {
        // SAFETY:
        // Safe because `VolatileSlice` is ABI-compatible with `IoBufMut`.
        unsafe { slice::from_raw_parts(iovs.as_ptr() as *const IoBufMut, iovs.len()) }
    }

    /// Converts a mutable slice of `VolatileSlice`s into a mutable slice of `IoBufMut`s
    #[inline]
    pub fn as_iobufs_mut<'mem, 'slice>(
        iovs: &'slice mut [VolatileSlice<'mem>],
    ) -> &'slice mut [IoBufMut<'mem>] {
        // SAFETY:
        // Safe because `VolatileSlice` is ABI-compatible with `IoBufMut`.
        unsafe { slice::from_raw_parts_mut(iovs.as_mut_ptr() as *mut IoBufMut, iovs.len()) }
    }

    /// Creates a copy of this slice with the address increased by `count` bytes, and the size
    /// reduced by `count` bytes.
    pub fn offset(self, count: usize) -> Result<VolatileSlice<'a>> {
        let new_addr = (self.as_mut_ptr() as usize).checked_add(count).ok_or(
            VolatileMemoryError::Overflow {
                base: self.as_mut_ptr() as usize,
                offset: count,
            },
        )?;
        let new_size = self
            .size()
            .checked_sub(count)
            .ok_or(VolatileMemoryError::OutOfBounds { addr: new_addr })?;

        // SAFETY:
        // Safe because the memory has the same lifetime and points to a subset of the memory of the
        // original slice.
        unsafe { Ok(VolatileSlice::from_raw_parts(new_addr as *mut u8, new_size)) }
    }

    /// Similar to `get_slice` but the returned slice outlives this slice.
    ///
    /// The returned slice's lifetime is still limited by the underlying data's lifetime.
    pub fn sub_slice(self, offset: usize, count: usize) -> Result<VolatileSlice<'a>> {
        let mem_end = offset
            .checked_add(count)
            .ok_or(VolatileMemoryError::Overflow {
                base: offset,
                offset: count,
            })?;
        if mem_end > self.size() {
            return Err(Error::OutOfBounds { addr: mem_end });
        }
        let new_addr = (self.as_mut_ptr() as usize).checked_add(offset).ok_or(
            VolatileMemoryError::Overflow {
                base: self.as_mut_ptr() as usize,
                offset,
            },
        )?;

        // SAFETY:
        // Safe because we have verified that the new memory is a subset of the original slice.
        Ok(unsafe { VolatileSlice::from_raw_parts(new_addr as *mut u8, count) })
    }

    /// Sets each byte of this slice with the given byte, similar to `memset`.
    ///
    /// The bytes of this slice are accessed in an arbitray order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use base::VolatileSlice;
    /// # fn test_write_45() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let vslice = VolatileSlice::new(&mut mem[..]);
    /// vslice.write_bytes(45);
    /// for &v in &mem[..] {
    ///     assert_eq!(v, 45);
    /// }
    /// # Ok(())
    /// # }
    pub fn write_bytes(&self, value: u8) {
        // SAFETY:
        // Safe because the memory is valid and needs only byte alignment.
        unsafe {
            write_bytes(self.as_mut_ptr(), value, self.size());
        }
    }

    /// Copies `self.size()` or `buf.len()` times the size of `T` bytes, whichever is smaller, to
    /// `buf`.
    ///
    /// The copy happens from smallest to largest address in `T` sized chunks using volatile reads.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use base::VolatileSlice;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let vslice = VolatileSlice::new(&mut mem[..]);
    /// let mut buf = [5u8; 16];
    /// vslice.copy_to(&mut buf[..]);
    /// for v in &buf[..] {
    ///     assert_eq!(buf[0], 0);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to<T>(&self, buf: &mut [T])
    where
        T: FromBytes + AsBytes + Copy,
    {
        let mut addr = self.as_mut_ptr() as *const u8;
        for v in buf.iter_mut().take(self.size() / size_of::<T>()) {
            // SAFETY: Safe because buf is valid, aligned to type `T` and is initialized.
            unsafe {
                *v = read_volatile(addr as *const T);
                addr = addr.add(size_of::<T>());
            }
        }
    }

    /// Copies `self.size()` or `slice.size()` bytes, whichever is smaller, to `slice`.
    ///
    /// The copies happen in an undefined order.
    /// # Examples
    ///
    /// ```
    /// # use base::VolatileMemory;
    /// # use base::VolatileSlice;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let vslice = VolatileSlice::new(&mut mem[..]);
    /// vslice.copy_to_volatile_slice(vslice.get_slice(16, 16).map_err(|_| ())?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to_volatile_slice(&self, slice: VolatileSlice) {
        // SAFETY: Safe because slice is valid and is byte aligned.
        unsafe {
            copy(
                self.as_mut_ptr() as *const u8,
                slice.as_mut_ptr(),
                min(self.size(), slice.size()),
            );
        }
    }

    /// Copies `self.size()` or `buf.len()` times the size of `T` bytes, whichever is smaller, to
    /// this slice's memory.
    ///
    /// The copy happens from smallest to largest address in `T` sized chunks using volatile writes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # use base::VolatileMemory;
    /// # use base::VolatileSlice;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let vslice = VolatileSlice::new(&mut mem[..]);
    /// let buf = [5u8; 64];
    /// vslice.copy_from(&buf[..]);
    /// let mut copy_buf = [0u32; 4];
    /// vslice.copy_to(&mut copy_buf);
    /// for i in 0..4 {
    ///     assert_eq!(copy_buf[i], 0x05050505);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_from<T>(&self, buf: &[T])
    where
        T: FromBytes + AsBytes,
    {
        let mut addr = self.as_mut_ptr();
        for v in buf.iter().take(self.size() / size_of::<T>()) {
            // SAFETY: Safe because buf is valid, aligned to type `T` and is mutable.
            unsafe {
                write_volatile(
                    addr as *mut T,
                    Ref::<_, T>::new(v.as_bytes()).unwrap().read(),
                );
                addr = addr.add(size_of::<T>());
            }
        }
    }

    /// Returns whether all bytes in this slice are zero or not.
    ///
    /// This is optimized for [VolatileSlice] aligned with 16 bytes.
    ///
    /// TODO(b/274840085): Use SIMD for better performance.
    pub fn is_all_zero(&self) -> bool {
        const MASK_4BIT: usize = 0x0f;
        let head_addr = self.as_ptr() as usize;
        // Round up by 16
        let aligned_head_addr = (head_addr + MASK_4BIT) & !MASK_4BIT;
        let tail_addr = head_addr + self.size();
        // Round down by 16
        let aligned_tail_addr = tail_addr & !MASK_4BIT;

        // Check 16 bytes at once. The addresses should be 16 bytes aligned for better performance.
        if (aligned_head_addr..aligned_tail_addr).step_by(16).any(
            |aligned_addr|
                // SAFETY: Each aligned_addr is within VolatileSlice
                unsafe { *(aligned_addr as *const u128) } != 0,
        ) {
            return false;
        }

        if head_addr == aligned_head_addr && tail_addr == aligned_tail_addr {
            // If head_addr and tail_addr are aligned, we can skip the unaligned part which contains
            // at least 2 conditional branches.
            true
        } else {
            // Check unaligned part.
            // SAFETY: The range [head_addr, aligned_head_addr) and [aligned_tail_addr, tail_addr)
            // are within VolatileSlice.
            unsafe {
                is_all_zero_naive(head_addr, aligned_head_addr)
                    && is_all_zero_naive(aligned_tail_addr, tail_addr)
            }
        }
    }
}

/// Check whether every byte is zero.
///
/// This checks byte by byte.
///
/// # Safety
///
/// * `head_addr` <= `tail_addr`
/// * Bytes between `head_addr` and `tail_addr` is valid to access.
unsafe fn is_all_zero_naive(head_addr: usize, tail_addr: usize) -> bool {
    (head_addr..tail_addr).all(|addr| *(addr as *const u8) == 0)
}

impl<'a> VolatileMemory for VolatileSlice<'a> {
    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
        self.sub_slice(offset, count)
    }
}

impl PartialEq<VolatileSlice<'_>> for VolatileSlice<'_> {
    fn eq(&self, other: &VolatileSlice) -> bool {
        let size = self.size();
        if size != other.size() {
            return false;
        }

        // SAFETY: We pass pointers into valid VolatileSlice regions, and size is checked above.
        let cmp = unsafe { libc::memcmp(self.as_ptr() as _, other.as_ptr() as _, size) };

        cmp == 0
    }
}

/// The `PartialEq` implementation for `VolatileSlice` is reflexive, symmetric, and transitive.
impl Eq for VolatileSlice<'_> {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread::spawn;

    use super::*;

    #[derive(Clone)]
    struct VecMem {
        mem: Arc<Vec<u8>>,
    }

    impl VecMem {
        fn new(size: usize) -> VecMem {
            VecMem {
                mem: Arc::new(vec![0u8; size]),
            }
        }
    }

    impl VolatileMemory for VecMem {
        fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
            let mem_end = offset
                .checked_add(count)
                .ok_or(VolatileMemoryError::Overflow {
                    base: offset,
                    offset: count,
                })?;
            if mem_end > self.mem.len() {
                return Err(Error::OutOfBounds { addr: mem_end });
            }

            let new_addr = (self.mem.as_ptr() as usize).checked_add(offset).ok_or(
                VolatileMemoryError::Overflow {
                    base: self.mem.as_ptr() as usize,
                    offset,
                },
            )?;

            Ok(
                // SAFETY: trivially safe
                unsafe { VolatileSlice::from_raw_parts(new_addr as *mut u8, count) },
            )
        }
    }

    #[test]
    fn observe_mutate() {
        let a = VecMem::new(1);
        let a_clone = a.clone();
        a.get_slice(0, 1).unwrap().write_bytes(99);

        let start_barrier = Arc::new(Barrier::new(2));
        let thread_start_barrier = start_barrier.clone();
        let end_barrier = Arc::new(Barrier::new(2));
        let thread_end_barrier = end_barrier.clone();
        spawn(move || {
            thread_start_barrier.wait();
            a_clone.get_slice(0, 1).unwrap().write_bytes(0);
            thread_end_barrier.wait();
        });

        let mut byte = [0u8; 1];
        a.get_slice(0, 1).unwrap().copy_to(&mut byte);
        assert_eq!(byte[0], 99);

        start_barrier.wait();
        end_barrier.wait();

        a.get_slice(0, 1).unwrap().copy_to(&mut byte);
        assert_eq!(byte[0], 0);
    }

    #[test]
    fn slice_size() {
        let a = VecMem::new(100);
        let s = a.get_slice(0, 27).unwrap();
        assert_eq!(s.size(), 27);

        let s = a.get_slice(34, 27).unwrap();
        assert_eq!(s.size(), 27);

        let s = s.get_slice(20, 5).unwrap();
        assert_eq!(s.size(), 5);
    }

    #[test]
    fn slice_overflow_error() {
        use std::usize::MAX;
        let a = VecMem::new(1);
        let res = a.get_slice(MAX, 1).unwrap_err();
        assert_eq!(
            res,
            Error::Overflow {
                base: MAX,
                offset: 1,
            }
        );
    }

    #[test]
    fn slice_oob_error() {
        let a = VecMem::new(100);
        a.get_slice(50, 50).unwrap();
        let res = a.get_slice(55, 50).unwrap_err();
        assert_eq!(res, Error::OutOfBounds { addr: 105 });
    }

    #[test]
    fn is_all_zero_16bytes_aligned() {
        let a = VecMem::new(1024);
        let slice = a.get_slice(0, 1024).unwrap();

        assert!(slice.is_all_zero());
        a.get_slice(129, 1).unwrap().write_bytes(1);
        assert!(!slice.is_all_zero());
    }

    #[test]
    fn is_all_zero_head_not_aligned() {
        let a = VecMem::new(1024);
        let slice = a.get_slice(1, 1023).unwrap();

        assert!(slice.is_all_zero());
        a.get_slice(0, 1).unwrap().write_bytes(1);
        assert!(slice.is_all_zero());
        a.get_slice(1, 1).unwrap().write_bytes(1);
        assert!(!slice.is_all_zero());
        a.get_slice(1, 1).unwrap().write_bytes(0);
        a.get_slice(129, 1).unwrap().write_bytes(1);
        assert!(!slice.is_all_zero());
    }

    #[test]
    fn is_all_zero_tail_not_aligned() {
        let a = VecMem::new(1024);
        let slice = a.get_slice(0, 1023).unwrap();

        assert!(slice.is_all_zero());
        a.get_slice(1023, 1).unwrap().write_bytes(1);
        assert!(slice.is_all_zero());
        a.get_slice(1022, 1).unwrap().write_bytes(1);
        assert!(!slice.is_all_zero());
        a.get_slice(1022, 1).unwrap().write_bytes(0);
        a.get_slice(0, 1).unwrap().write_bytes(1);
        assert!(!slice.is_all_zero());
    }

    #[test]
    fn is_all_zero_no_aligned_16bytes() {
        let a = VecMem::new(1024);
        let slice = a.get_slice(1, 16).unwrap();

        assert!(slice.is_all_zero());
        a.get_slice(0, 1).unwrap().write_bytes(1);
        assert!(slice.is_all_zero());
        for i in 1..17 {
            a.get_slice(i, 1).unwrap().write_bytes(1);
            assert!(!slice.is_all_zero());
            a.get_slice(i, 1).unwrap().write_bytes(0);
        }
        a.get_slice(17, 1).unwrap().write_bytes(1);
        assert!(slice.is_all_zero());
    }
}

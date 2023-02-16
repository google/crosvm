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
#![allow(deprecated)]

use std::cmp::min;
use std::marker::PhantomData;
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
use zerocopy::LayoutVerified;

use crate::sys::IoBufMut;
use crate::DataInit;

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

/// Convenience function for computing `base + offset` which returns
/// `Err(VolatileMemoryError::Overflow)` instead of panicking in the case `base + offset` exceeds
/// `u64::MAX`.
///
/// # Examples
///
/// ```
/// # use data_model::*;
/// # fn get_slice(offset: usize, count: usize) -> VolatileMemoryResult<()> {
///   let mem_end = calc_offset(offset, count)?;
///   if mem_end > 100 {
///       return Err(VolatileMemoryError::OutOfBounds{addr: mem_end});
///   }
/// # Ok(())
/// # }
/// ```
pub fn calc_offset(base: usize, offset: usize) -> Result<usize> {
    match base.checked_add(offset) {
        None => Err(Error::Overflow { base, offset }),
        Some(m) => Ok(m),
    }
}

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
        // Safe because `VolatileSlice` is ABI-compatible with `IoBufMut`.
        unsafe { slice::from_raw_parts(iovs.as_ptr() as *const IoBufMut, iovs.len()) }
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

        // Safe because the memory has the same lifetime and points to a subset of the memory of the
        // original slice.
        unsafe { Ok(VolatileSlice::from_raw_parts(new_addr as *mut u8, new_size)) }
    }

    /// Similar to `get_slice` but the returned slice outlives this slice.
    ///
    /// The returned slice's lifetime is still limited by the underlying data's lifetime.
    pub fn sub_slice(self, offset: usize, count: usize) -> Result<VolatileSlice<'a>> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.size() {
            return Err(Error::OutOfBounds { addr: mem_end });
        }
        let new_addr = (self.as_mut_ptr() as usize).checked_add(offset).ok_or(
            VolatileMemoryError::Overflow {
                base: self.as_mut_ptr() as usize,
                offset,
            },
        )?;

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
    /// # use data_model::VolatileSlice;
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
    /// # use data_model::VolatileSlice;
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
        T: DataInit,
    {
        let mut addr = self.as_mut_ptr() as *const u8;
        for v in buf.iter_mut().take(self.size() / size_of::<T>()) {
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
    /// # use data_model::{VolatileMemory, VolatileSlice};
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let vslice = VolatileSlice::new(&mut mem[..]);
    /// vslice.copy_to_volatile_slice(vslice.get_slice(16, 16).map_err(|_| ())?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to_volatile_slice(&self, slice: VolatileSlice) {
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
    /// # use data_model::{VolatileMemory, VolatileSlice};
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
            unsafe {
                write_volatile(
                    addr as *mut T,
                    LayoutVerified::<_, T>::new(v.as_bytes()).unwrap().read(),
                );
                addr = addr.add(size_of::<T>());
            }
        }
    }
}

impl<'a> VolatileMemory for VolatileSlice<'a> {
    fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
        self.sub_slice(offset, count)
    }
}

/// A memory location that supports volatile access of a `T`.
///
/// # Examples
///
/// ```
/// # use data_model::VolatileRef;
///   let mut v = 5u32;
///   assert_eq!(v, 5);
///   let v_ref = unsafe { VolatileRef::new(&mut v as *mut u32) };
///   assert_eq!(v_ref.load(), 5);
///   v_ref.store(500);
///   assert_eq!(v, 500);
#[deprecated(
    note = "This is an unsafe abstraction. Users should use alternatives such as read_obj() and 
    write_obj() that do not create a long-lived mutable reference that could easily alias other 
    slices"
)]
#[derive(Debug)]
pub struct VolatileRef<'a, T: DataInit>
where
    T: 'a,
{
    addr: *mut T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T: DataInit> VolatileRef<'a, T> {
    /// Creates a reference to raw memory that must support volatile access of `T` sized chunks.
    ///
    /// # Safety
    /// To use this safely, the caller must guarantee that the memory at `addr` is big enough for a
    /// `T` and is available for the duration of the lifetime of the new `VolatileRef`. The caller
    /// must also guarantee that all other users of the given chunk of memory are using volatile
    /// accesses.
    pub unsafe fn new(addr: *mut T) -> VolatileRef<'a, T> {
        VolatileRef {
            addr,
            phantom: PhantomData,
        }
    }

    /// Gets the size of this slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::mem::size_of;
    /// # use data_model::VolatileRef;
    ///   let v_ref = unsafe { VolatileRef::new(0 as *mut u32) };
    ///   assert_eq!(v_ref.size(), size_of::<u32>());
    /// ```
    pub fn size(&self) -> usize {
        size_of::<T>()
    }

    /// Does a volatile write of the value `v` to the address of this ref.
    #[inline(always)]
    pub fn store(&self, v: T) {
        unsafe { write_volatile(self.addr, v) };
    }

    /// Does a volatile read of the value at the address of this ref.
    #[inline(always)]
    pub fn load(&self) -> T {
        // For the purposes of demonstrating why read_volatile is necessary, try replacing the code
        // in this function with the commented code below and running `cargo test --release`.
        // unsafe { *(self.addr as *const T) }
        unsafe { read_volatile(self.addr) }
    }
}

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
            let mut mem = Vec::new();
            mem.resize(size, 0);
            VecMem { mem: Arc::new(mem) }
        }
    }

    impl VolatileMemory for VecMem {
        fn get_slice(&self, offset: usize, count: usize) -> Result<VolatileSlice> {
            let mem_end = calc_offset(offset, count)?;
            if mem_end > self.mem.len() {
                return Err(Error::OutOfBounds { addr: mem_end });
            }

            let new_addr = (self.mem.as_ptr() as usize).checked_add(offset).ok_or(
                VolatileMemoryError::Overflow {
                    base: self.mem.as_ptr() as usize,
                    offset,
                },
            )?;

            Ok(unsafe { VolatileSlice::from_raw_parts(new_addr as *mut u8, count) })
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
}

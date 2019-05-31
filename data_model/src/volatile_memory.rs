// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Types for volatile access to memory.
//!
//! Two of the core rules for safe rust is no data races and no aliased mutable references.
//! `VolatileRef` and `VolatileSlice`, along with types that produce those which implement
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
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::mem::size_of;
use std::ptr::{copy, null_mut, read_volatile, write_bytes, write_volatile};
use std::result;
use std::{isize, usize};

use crate::DataInit;

#[derive(Eq, PartialEq, Debug)]
pub enum VolatileMemoryError {
    /// `addr` is out of bounds of the volatile memory slice.
    OutOfBounds { addr: u64 },
    /// Taking a slice at `base` with `offset` would overflow `u64`.
    Overflow { base: u64, offset: u64 },
}

impl Display for VolatileMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VolatileMemoryError::*;

        match self {
            OutOfBounds { addr } => write!(f, "address 0x{:x} is out of bounds", addr),
            Overflow { base, offset } => write!(
                f,
                "address 0x{:x} offset by 0x{:x} would overflow",
                base, offset
            ),
        }
    }
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
/// # fn get_slice(offset: u64, count: u64) -> VolatileMemoryResult<()> {
///   let mem_end = calc_offset(offset, count)?;
///   if mem_end > 100 {
///       return Err(VolatileMemoryError::OutOfBounds{addr: mem_end});
///   }
/// # Ok(())
/// # }
/// ```
pub fn calc_offset(base: u64, offset: u64) -> Result<u64> {
    match base.checked_add(offset) {
        None => Err(Error::Overflow { base, offset }),
        Some(m) => Ok(m),
    }
}

/// Trait for types that support raw volatile access to their data.
pub trait VolatileMemory {
    /// Gets a slice of memory at `offset` that is `count` bytes in length and supports volatile
    /// access.
    fn get_slice(&self, offset: u64, count: u64) -> Result<VolatileSlice>;

    /// Gets a `VolatileRef` at `offset`.
    fn get_ref<T: DataInit>(&self, offset: u64) -> Result<VolatileRef<T>> {
        let slice = self.get_slice(offset, size_of::<T>() as u64)?;
        Ok(VolatileRef {
            addr: slice.addr as *mut T,
            phantom: PhantomData,
        })
    }
}

impl<'a> VolatileMemory for &'a mut [u8] {
    fn get_slice(&self, offset: u64, count: u64) -> Result<VolatileSlice> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.len() as u64 {
            return Err(Error::OutOfBounds { addr: mem_end });
        }
        Ok(unsafe { VolatileSlice::new((self.as_ptr() as u64 + offset) as *mut _, count) })
    }
}

/// A slice of raw memory that supports volatile access.
#[derive(Copy, Clone, Debug)]
pub struct VolatileSlice<'a> {
    addr: *mut u8,
    size: u64,
    phantom: PhantomData<&'a u8>,
}

impl<'a> Default for VolatileSlice<'a> {
    fn default() -> VolatileSlice<'a> {
        VolatileSlice {
            addr: null_mut(),
            size: 0,
            phantom: PhantomData,
        }
    }
}

impl<'a> VolatileSlice<'a> {
    /// Creates a slice of raw memory that must support volatile access.
    ///
    /// To use this safely, the caller must guarantee that the memory at `addr` is `size` bytes long
    /// and is available for the duration of the lifetime of the new `VolatileSlice`. The caller
    /// must also guarantee that all other users of the given chunk of memory are using volatile
    /// accesses.
    pub unsafe fn new(addr: *mut u8, size: u64) -> VolatileSlice<'a> {
        VolatileSlice {
            addr,
            size,
            phantom: PhantomData,
        }
    }

    /// Gets the address of this slice's memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Gets the size of this slice.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Creates a copy of this slice with the address increased by `count` bytes, and the size
    /// reduced by `count` bytes.
    pub fn offset(self, count: u64) -> Result<VolatileSlice<'a>> {
        let new_addr =
            (self.addr as u64)
                .checked_add(count)
                .ok_or(VolatileMemoryError::Overflow {
                    base: self.addr as u64,
                    offset: count,
                })?;
        if new_addr > usize::MAX as u64 {
            return Err(VolatileMemoryError::Overflow {
                base: self.addr as u64,
                offset: count,
            })?;
        }
        let new_size = self
            .size
            .checked_sub(count)
            .ok_or(VolatileMemoryError::OutOfBounds { addr: new_addr })?;
        // Safe because the memory has the same lifetime and points to a subset of the memory of the
        // original slice.
        unsafe { Ok(VolatileSlice::new(new_addr as *mut u8, new_size)) }
    }

    /// Sets each byte of this slice with the given byte, similar to `memset`.
    ///
    /// The bytes of this slice are accessed in an arbitray order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use data_model::VolatileMemory;
    /// # fn test_write_45() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// vslice.write_bytes(45);
    /// for &mut v in mem_ref {
    ///     assert_eq!(v, 45);
    /// }
    /// # Ok(())
    /// # }
    pub fn write_bytes(&self, value: u8) {
        // Safe because the memory is valid and needs only byte alignment.
        unsafe {
            write_bytes(self.as_ptr(), value, self.size as usize);
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
    /// # use data_model::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
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
        let mut addr = self.addr;
        for v in buf.iter_mut().take(self.size as usize / size_of::<T>()) {
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
    /// # use data_model::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// vslice.copy_to_volatile_slice(vslice.get_slice(16, 16).map_err(|_| ())?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_to_volatile_slice(&self, slice: VolatileSlice) {
        unsafe {
            copy(self.addr, slice.addr, min(self.size, slice.size) as usize);
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
    /// # use data_model::VolatileMemory;
    /// # fn test_write_null() -> Result<(), ()> {
    /// let mut mem = [0u8; 32];
    /// let mem_ref = &mut mem[..];
    /// let vslice = mem_ref.get_slice(0, 32).map_err(|_| ())?;
    /// let buf = [5u8; 64];
    /// vslice.copy_from(&buf[..]);
    /// for i in 0..4 {
    ///     assert_eq!(vslice.get_ref::<u32>(i * 4).map_err(|_| ())?.load(), 0x05050505);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn copy_from<T>(&self, buf: &[T])
    where
        T: DataInit,
    {
        let mut addr = self.addr;
        for &v in buf.iter().take(self.size as usize / size_of::<T>()) {
            unsafe {
                write_volatile(addr as *mut T, v);
                addr = addr.add(size_of::<T>());
            }
        }
    }
}

impl<'a> VolatileMemory for VolatileSlice<'a> {
    fn get_slice(&self, offset: u64, count: u64) -> Result<VolatileSlice> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.size {
            return Err(Error::OutOfBounds { addr: mem_end });
        }
        Ok(VolatileSlice {
            addr: (self.addr as u64 + offset) as *mut _,
            size: count,
            phantom: PhantomData,
        })
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

    /// Gets the address of this slice's memory.
    pub fn as_ptr(&self) -> *mut T {
        self.addr
    }

    /// Gets the size of this slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::mem::size_of;
    /// # use data_model::VolatileRef;
    ///   let v_ref = unsafe { VolatileRef::new(0 as *mut u32) };
    ///   assert_eq!(v_ref.size(), size_of::<u32>() as u64);
    /// ```
    pub fn size(&self) -> u64 {
        size_of::<T>() as u64
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

    /// Converts this `T` reference to a raw slice with the same size and address.
    pub fn to_slice(&self) -> VolatileSlice<'a> {
        unsafe { VolatileSlice::new(self.addr as *mut u8, size_of::<T>() as u64) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::thread::{sleep, spawn};
    use std::time::Duration;

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
        fn get_slice(&self, offset: u64, count: u64) -> Result<VolatileSlice> {
            let mem_end = calc_offset(offset, count)?;
            if mem_end > self.mem.len() as u64 {
                return Err(Error::OutOfBounds { addr: mem_end });
            }
            Ok(unsafe { VolatileSlice::new((self.mem.as_ptr() as u64 + offset) as *mut _, count) })
        }
    }

    #[test]
    fn ref_store() {
        let mut a = [0u8; 1];
        let a_ref = &mut a[..];
        let v_ref = a_ref.get_ref(0).unwrap();
        v_ref.store(2u8);
        assert_eq!(a[0], 2);
    }

    #[test]
    fn ref_load() {
        let mut a = [5u8; 1];
        {
            let a_ref = &mut a[..];
            let c = {
                let v_ref = a_ref.get_ref::<u8>(0).unwrap();
                assert_eq!(v_ref.load(), 5u8);
                v_ref
            };
            // To make sure we can take a v_ref out of the scope we made it in:
            c.load();
            // but not too far:
            // c
        } //.load()
        ;
    }

    #[test]
    fn ref_to_slice() {
        let mut a = [1u8; 5];
        let a_ref = &mut a[..];
        let v_ref = a_ref.get_ref(1).unwrap();
        v_ref.store(0x12345678u32);
        let ref_slice = v_ref.to_slice();
        assert_eq!(v_ref.as_ptr() as u64, ref_slice.as_ptr() as u64);
        assert_eq!(v_ref.size(), ref_slice.size());
    }

    #[test]
    fn observe_mutate() {
        let a = VecMem::new(1);
        let a_clone = a.clone();
        let v_ref = a.get_ref::<u8>(0).unwrap();
        v_ref.store(99);
        spawn(move || {
            sleep(Duration::from_millis(10));
            let clone_v_ref = a_clone.get_ref::<u8>(0).unwrap();
            clone_v_ref.store(0);
        });

        // Technically this is a race condition but we have to observe the v_ref's value changing
        // somehow and this helps to ensure the sleep actually happens before the store rather then
        // being reordered by the compiler.
        assert_eq!(v_ref.load(), 99);

        // Granted we could have a machine that manages to perform this many volatile loads in the
        // amount of time the spawned thread sleeps, but the most likely reason the retry limit will
        // get reached is because v_ref.load() is not actually performing the required volatile read
        // or v_ref.store() is not doing a volatile write. A timer based solution was avoided
        // because that might use a syscall which could hint the optimizer to reload v_ref's pointer
        // regardless of volatile status. Note that we use a longer retry duration for optimized
        // builds.
        #[cfg(debug_assertions)]
        const RETRY_MAX: u64 = 500_000_000;
        #[cfg(not(debug_assertions))]
        const RETRY_MAX: u64 = 10_000_000_000;

        let mut retry = 0;
        while v_ref.load() == 99 && retry < RETRY_MAX {
            retry += 1;
        }

        assert_ne!(retry, RETRY_MAX, "maximum retry exceeded");
        assert_eq!(v_ref.load(), 0);
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
        use std::u64::MAX;
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
    fn ref_overflow_error() {
        use std::u64::MAX;
        let a = VecMem::new(1);
        let res = a.get_ref::<u8>(MAX).unwrap_err();
        assert_eq!(
            res,
            Error::Overflow {
                base: MAX,
                offset: 1,
            }
        );
    }

    #[test]
    fn ref_oob_error() {
        let a = VecMem::new(100);
        a.get_ref::<u8>(99).unwrap();
        let res = a.get_ref::<u16>(99).unwrap_err();
        assert_eq!(res, Error::OutOfBounds { addr: 101 });
    }

    #[test]
    fn ref_oob_too_large() {
        let a = VecMem::new(3);
        let res = a.get_ref::<u32>(0).unwrap_err();
        assert_eq!(res, Error::OutOfBounds { addr: 4 });
    }
}

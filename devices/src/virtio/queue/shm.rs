// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Raw shared-memory primitives for the virtqueue layer.
//!
//! All raw-pointer and `VolatileSlice` operations used by `SplitQueue`, `PackedQueue`,
//! `SplitDescriptorChain`, `PackedDescriptorChain`, `Reader`, and `Writer` are isolated in this
//! module so the rest of the virtqueue subsystem compiles under `#![deny(unsafe_code)]`.

use std::cmp;
use std::io;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use cros_async::MemRegionIter;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

/// Atomically loads a little-endian `u16` from `addr` with `Ordering::Relaxed`.
///
/// Fails if `addr` is out of bounds or not 2-byte aligned in host memory.
pub fn load_u16(mem: &GuestMemory, addr: GuestAddress) -> Result<u16> {
    let vslice = mem
        .get_slice_at_addr(addr, 2)
        .with_context(|| format!("failed to load u16 at {:#x}", addr.offset()))?;
    let ptr = vslice.as_mut_ptr() as *mut u16;
    ensure!(
        ptr.is_aligned(),
        "unaligned u16 load at {:#x}",
        addr.offset()
    );
    // SAFETY: `ptr` points to 2 valid bytes of `vslice` and is 2-byte aligned. A single relaxed
    // `AtomicU16` load performs one access without tearing and avoids data-race UB under
    // concurrent guest writes.
    Ok(u16::from_le(
        unsafe { AtomicU16::from_ptr(ptr) }.load(Ordering::Relaxed),
    ))
}

/// Atomically stores a little-endian `u16` at `addr` with `Ordering::Relaxed`.
///
/// Fails if `addr` is out of bounds or not 2-byte aligned in host memory.
pub fn store_u16(mem: &GuestMemory, addr: GuestAddress, val: u16) -> Result<()> {
    let vslice = mem
        .get_slice_at_addr(addr, 2)
        .with_context(|| format!("failed to store u16 at {:#x}", addr.offset()))?;
    let ptr = vslice.as_mut_ptr() as *mut u16;
    ensure!(
        ptr.is_aligned(),
        "unaligned u16 store at {:#x}",
        addr.offset()
    );
    // SAFETY: `ptr` points to 2 valid bytes of `vslice` and is 2-byte aligned. A single relaxed
    // `AtomicU16` store avoids byte tearing on SMP guests.
    unsafe { AtomicU16::from_ptr(ptr) }.store(val.to_le(), Ordering::Relaxed);
    Ok(())
}

/// Atomically loads a little-endian `u32` from `addr` with `Ordering::Relaxed`.
///
/// Fails if `addr` is out of bounds or not 4-byte aligned in host memory.
pub fn load_u32(mem: &GuestMemory, addr: GuestAddress) -> Result<u32> {
    let vslice = mem
        .get_slice_at_addr(addr, 4)
        .with_context(|| format!("failed to load u32 at {:#x}", addr.offset()))?;
    let ptr = vslice.as_mut_ptr() as *mut u32;
    ensure!(
        ptr.is_aligned(),
        "unaligned u32 load at {:#x}",
        addr.offset()
    );
    // SAFETY: `ptr` points to 4 valid bytes of `vslice` and is 4-byte aligned. A single relaxed
    // `AtomicU32` load avoids tearing between adjacent fields on SMP guests.
    Ok(u32::from_le(
        unsafe { AtomicU32::from_ptr(ptr) }.load(Ordering::Relaxed),
    ))
}

/// Atomically stores a little-endian `u32` at `addr` with `Ordering::Relaxed`.
///
/// Fails if `addr` is out of bounds or not 4-byte aligned in host memory.
pub fn store_u32(mem: &GuestMemory, addr: GuestAddress, val: u32) -> Result<()> {
    let vslice = mem
        .get_slice_at_addr(addr, 4)
        .with_context(|| format!("failed to store u32 at {:#x}", addr.offset()))?;
    let ptr = vslice.as_mut_ptr() as *mut u32;
    ensure!(
        ptr.is_aligned(),
        "unaligned u32 store at {:#x}",
        addr.offset()
    );
    // SAFETY: `ptr` points to 4 valid bytes of `vslice` and is 4-byte aligned. A single relaxed
    // `AtomicU32` store avoids tearing between adjacent fields on SMP guests.
    unsafe { AtomicU32::from_ptr(ptr) }.store(val.to_le(), Ordering::Relaxed);
    Ok(())
}

/// Checks that `addr` is `align`-byte aligned in host memory.
///
/// `GuestMemory` does not require region bases to be aligned, so an aligned guest address can
/// still be unaligned in host memory. Fails if `addr` is out of bounds or unaligned.
pub fn check_host_aligned(mem: &GuestMemory, addr: GuestAddress, align: u64) -> Result<()> {
    let vslice = mem
        .get_slice_at_addr(addr, 1)
        .with_context(|| format!("failed to translate {:#x}", addr.offset()))?;
    ensure!(
        vslice.as_mut_ptr().addr() as u64 % align == 0,
        "{:#x} is not {}-byte aligned in host memory",
        addr.offset(),
        align
    );
    Ok(())
}

/// Reads an object of type `T` from `addr`, loading each byte atomically with
/// `Ordering::Relaxed`.
pub fn read_obj<T: FromBytes + IntoBytes>(mem: &GuestMemory, addr: GuestAddress) -> Result<T> {
    let size = size_of::<T>();
    let vslice = mem
        .get_slice_at_addr(addr, size)
        .with_context(|| format!("failed to read {} bytes at {:#x}", size, addr.offset()))?;
    let p = vslice.as_mut_ptr();
    let mut obj = T::new_zeroed();
    for (i, slot) in obj.as_mut_bytes().iter_mut().enumerate() {
        // SAFETY: `i < size_of::<T>()` is in bounds of `vslice`.
        *slot = unsafe { AtomicU8::from_ptr(p.add(i)).load(Ordering::Relaxed) };
    }
    Ok(obj)
}

/// Copy up to `size` bytes from `src` into `dst`.
///
/// Returns the total number of bytes copied.
///
/// # Safety
///
/// The caller must ensure that it is safe to write `size` bytes of data into `dst`.
///
/// After the function returns, it is only safe to assume that the number of bytes indicated by the
/// return value (which may be less than the requested `size`) have been initialized. Bytes beyond
/// that point are not initialized by this function.
unsafe fn copy_regions_to_mut_ptr(
    mem: &GuestMemory,
    src: MemRegionIter,
    dst: *mut u8,
    size: usize,
) -> io::Result<usize> {
    let mut copied = 0;
    for src_region in src {
        if copied >= size {
            break;
        }

        let remaining = size - copied;
        let count = cmp::min(remaining, src_region.len);

        let vslice = mem
            .get_slice_at_addr(GuestAddress(src_region.offset), count)
            .map_err(|_e| io::Error::from(io::ErrorKind::InvalidData))?;

        // SAFETY: `get_slice_at_addr()` verified that the region points to valid memory, and
        // the `count` calculation ensures we will write at most `size` bytes into `dst`.
        unsafe {
            copy_nonoverlapping(vslice.as_ptr(), dst.add(copied), count);
        }

        copied += count;
    }

    Ok(copied)
}

/// Reads an object of type `T` from `src` without consuming regions, returning `(obj,
/// size_of::<T>())`.
pub fn peek_obj_from_regions<T: FromBytes>(
    mem: &GuestMemory,
    src: MemRegionIter,
) -> io::Result<(T, usize)> {
    let mut obj = MaybeUninit::<T>::uninit();
    let needed = size_of::<T>();
    // SAFETY: We pass a valid pointer and size of `obj`.
    let copied = unsafe { copy_regions_to_mut_ptr(mem, src, obj.as_mut_ptr() as *mut u8, needed)? };
    if copied != needed {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    // SAFETY: `FromBytes` guarantees any set of initialized bytes is a valid value for `T`, and
    // we initialized all bytes in `obj` in the copy above.
    Ok((unsafe { obj.assume_init() }, needed))
}

/// Copies bytes from `src` regions in `mem` into `buf`, returning the number of bytes copied.
pub fn copy_regions_to_slice(
    mem: &GuestMemory,
    src: MemRegionIter,
    buf: &mut [u8],
) -> io::Result<usize> {
    // SAFETY: We pass a valid pointer and size combination derived from `buf`.
    unsafe { copy_regions_to_mut_ptr(mem, src, buf.as_mut_ptr(), buf.len()) }
}

/// Copies bytes from `src` into the destination `dst` regions in `mem`, returning the total number
/// of bytes written.
pub fn copy_slice_to_regions(
    mem: &GuestMemory,
    dst: MemRegionIter,
    src: &[u8],
) -> io::Result<usize> {
    let mut rem = src;
    let mut total = 0;
    for region in dst {
        if rem.is_empty() {
            break;
        }
        let count = cmp::min(rem.len(), region.len);
        let vslice = mem
            .get_slice_at_addr(GuestAddress(region.offset), count)
            .map_err(|_e| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY:
        // Safe because we have already verified that `vs` points to valid memory.
        unsafe {
            copy_nonoverlapping(rem.as_ptr(), vslice.as_mut_ptr(), count);
        }
        rem = &rem[count..];
        total += count;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use cros_async::MemRegion;

    use super::*;

    #[test]
    fn load_store_round_trip_little_endian() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();

        store_u16(&mem, GuestAddress(0x10), 0x1234).unwrap();
        assert_eq!(load_u16(&mem, GuestAddress(0x10)).unwrap(), 0x1234);
        assert_eq!(
            mem.read_obj_from_addr::<[u8; 2]>(GuestAddress(0x10))
                .unwrap(),
            [0x34, 0x12]
        );

        store_u32(&mem, GuestAddress(0x20), 0x1234_5678).unwrap();
        assert_eq!(load_u32(&mem, GuestAddress(0x20)).unwrap(), 0x1234_5678);
        assert_eq!(
            mem.read_obj_from_addr::<[u8; 4]>(GuestAddress(0x20))
                .unwrap(),
            [0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn load_store_reject_unaligned_and_out_of_bounds() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();

        assert!(load_u16(&mem, GuestAddress(0x11)).is_err());
        assert!(store_u16(&mem, GuestAddress(0x11), 0).is_err());
        assert!(load_u32(&mem, GuestAddress(0x22)).is_err());
        assert!(store_u32(&mem, GuestAddress(0x22), 0).is_err());

        assert!(load_u16(&mem, GuestAddress(0xfff)).is_err());
        assert!(load_u32(&mem, GuestAddress(0x1000)).is_err());
    }

    #[test]
    fn check_host_aligned_uses_host_address() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        assert!(check_host_aligned(&mem, GuestAddress(0x10), 16).is_ok());
        assert!(check_host_aligned(&mem, GuestAddress(0x12), 4).is_err());
        assert!(check_host_aligned(&mem, GuestAddress(0x1000), 1).is_err());

        // The region base is page-aligned in host memory but not in guest memory, so guest
        // address 0x1002 is 2-byte aligned only in guest memory.
        let mem = GuestMemory::new(&[(GuestAddress(0x1001), 0x1000)]).unwrap();
        assert!(check_host_aligned(&mem, GuestAddress(0x1002), 2).is_err());
        assert!(check_host_aligned(&mem, GuestAddress(0x1003), 2).is_ok());
        assert!(load_u16(&mem, GuestAddress(0x1002)).is_err());
    }

    #[test]
    fn copy_slice_to_regions_rejects_invalid_region() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let regions = [
            MemRegion {
                offset: 0x2000,
                len: 4,
            },
            MemRegion {
                offset: 0x10,
                len: 4,
            },
        ];

        let err =
            copy_slice_to_regions(&mem, MemRegionIter::new(&regions), &[1, 2, 3, 4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            mem.read_obj_from_addr::<[u8; 4]>(GuestAddress(0x10))
                .unwrap(),
            [0; 4]
        );
    }
}

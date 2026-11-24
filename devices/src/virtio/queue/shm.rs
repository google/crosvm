// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Raw shared-memory primitives for virtqueue ring and descriptor accesses.
//!
//! All raw-pointer atomic operations used for `SplitQueue` and `PackedQueue` ring accesses, the
//! host alignment check that rings are validated with, and `SplitDescriptorChain` and
//! `PackedDescriptorChain` descriptor reads are isolated in this module.

use std::mem::size_of;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
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

#[cfg(test)]
mod tests {
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
}

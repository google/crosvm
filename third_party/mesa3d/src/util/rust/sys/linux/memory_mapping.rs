// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::ffi::c_void;
use std::os::fd::AsFd;
use std::ptr::null_mut;

use rustix::mm::mmap;
use rustix::mm::munmap;
use rustix::mm::MapFlags;
use rustix::mm::ProtFlags;

use crate::MesaError;
use crate::MesaResult;
use crate::OwnedDescriptor;
use crate::MESA_MAP_ACCESS_MASK;
use crate::MESA_MAP_ACCESS_READ;
use crate::MESA_MAP_ACCESS_RW;
use crate::MESA_MAP_ACCESS_WRITE;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub addr: *mut c_void,
    pub size: usize,
}

// SAFETY:
// MemoryMapping user must ensure it is used by one thread at a time.
unsafe impl Sync for MemoryMapping {}
// SAFETY:
// MemoryMapping user must ensure it is used by one thread at a time.
unsafe impl Send for MemoryMapping {}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // SAFETY:
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            munmap(self.addr, self.size).unwrap();
        }
    }
}

impl MemoryMapping {
    fn do_mmap(
        descriptor: &OwnedDescriptor,
        offset: usize,
        size: usize,
        map_info: u32,
    ) -> MesaResult<MemoryMapping> {
        let prot = match map_info & MESA_MAP_ACCESS_MASK {
            MESA_MAP_ACCESS_READ => ProtFlags::READ,
            MESA_MAP_ACCESS_WRITE => ProtFlags::WRITE,
            MESA_MAP_ACCESS_RW => ProtFlags::READ | ProtFlags::WRITE,
            _ => return Err(MesaError::WithContext("incorrect access flags")),
        };

        // SAFETY:
        // The inputs to the mmap() system call have been verified, and
        // the kernel is trusted to deliver a correct result.
        let addr = unsafe {
            mmap(
                null_mut(),
                size,
                prot,
                MapFlags::SHARED,
                descriptor.as_fd(),
                offset.try_into().unwrap(),
            )?
        };

        Ok(MemoryMapping { addr, size })
    }

    pub fn from_safe_descriptor(
        descriptor: OwnedDescriptor,
        size: usize,
        map_info: u32,
    ) -> MesaResult<MemoryMapping> {
        Self::do_mmap(&descriptor, 0, size, map_info)
    }

    pub fn from_offset(
        descriptor: &OwnedDescriptor,
        offset: usize,
        size: usize,
    ) -> MesaResult<MemoryMapping> {
        Self::do_mmap(descriptor, offset, size, MESA_MAP_ACCESS_RW)
    }
}

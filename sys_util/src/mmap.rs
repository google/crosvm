// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std;
use std::ptr::null_mut;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc;

use {Result, errno_result};

/// Wraps an anonymous shared memory mapping in the current process.
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
    ref_count: Arc<AtomicUsize>,
}

unsafe impl Send for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        let addr = unsafe {
            libc::mmap(null_mut(),
                       size,
                       libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                       -1,
                       0)
        };
        if addr == null_mut() {
            return errno_result();
        }
        Ok(MemoryMapping {
               addr: addr as *mut u8,
               size: size,
               ref_count: Arc::new(AtomicUsize::new(1)),
           })
    }

    /// Maps the first `size` bytes of the given `fd`.
    pub fn from_fd(fd: &AsRawFd, size: usize) -> Result<MemoryMapping> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(null_mut(),
                       size,
                       libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_SHARED,
                       fd.as_raw_fd(),
                       0)
        };
        if addr == null_mut() {
            return errno_result();
        }
        Ok(MemoryMapping {
               addr: addr as *mut u8,
               size: size,
               ref_count: Arc::new(AtomicUsize::new(1)),
           })
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    #[deprecated(note="use volatile_read with the ptr instead")]
    pub fn as_slice(&self) -> &[u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias, hence the deprecation.
        unsafe { std::slice::from_raw_parts(self.addr, self.size) }
    }

    #[deprecated(note="use volatile_write with the ptr instead")]
    pub fn as_mut_slice(&self) -> &mut [u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias, hence the deprecation.
        unsafe { std::slice::from_raw_parts_mut(self.addr, self.size) }
    }

    // TODO(zachr): remove when we no longer need it, clone is sketchy
    pub fn clone(&self) -> MemoryMapping {
        self.ref_count.fetch_add(1, Ordering::SeqCst);
        MemoryMapping {
            addr: self.addr,
            size: self.size,
            ref_count: self.ref_count.clone(),
        }
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        if self.ref_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            // This is safe because we mmap the area at addr ourselves, and the ref_count ensures
            // nobody else is holding a reference to it.
            unsafe {
                libc::munmap(self.addr as *mut libc::c_void, self.size);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic_map() {
        let m = MemoryMapping::new(1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn mutate_slices() {
        let m = MemoryMapping::new(1024).unwrap();
        assert_eq!(1024, m.size());
        {
            m.as_mut_slice()[128] = 55;
        }
        assert_eq!(m.as_slice()[128], 55);
    }
}

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std;
use std::io::{Read, Write};
use std::ptr::null_mut;
use std::os::unix::io::AsRawFd;

use libc;

use errno;

#[derive(Debug)]
pub enum Error {
    /// Requested memory out of range.
    InvalidAddress,
    /// Couldn't read from the given source.
    ReadFromSource,
    /// `mmap` returned the given error.
    SystemCallFailed(errno::Error),
    /// Wrting to memory failed
    WriteToMemory(std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Wraps an anonymous shared memory mapping in the current process.
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
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
        if addr.is_null() {
            return Err(Error::SystemCallFailed(errno::Error::last()));
        }
        Ok(MemoryMapping {
               addr: addr as *mut u8,
               size: size,
           })
    }

    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
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
        if addr.is_null() {
            return Err(Error::SystemCallFailed(errno::Error::last()));
        }
        Ok(MemoryMapping {
               addr: addr as *mut u8,
               size: size,
           })
    }

    /// Returns a pointer to the begining of the memory region.  Should only be
    /// used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Writes a slice to the memory region at the specified offset.
    /// Returns Ok(<number of bytes written>).  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at offset 256.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_slice(&[1,2,3,4,5], 0);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 5);
    /// ```
    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        if offset >= self.size {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            let mut slice: &mut [u8] = &mut self.as_mut_slice()[offset..];
            Ok(slice.write(buf).map_err(Error::WriteToMemory)?)
        }
    }

    /// Writes an object to the memory region at the specified offset.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at offset 16.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj<T>(&self, val: T, offset: usize) -> Result<()> {
        unsafe {
            // Guest memory can't strictly be modeled as a slice because it is
            // volatile.  Writing to it with what compiles down to a memcpy
            // won't hurt anything as long as we get the bounds checks right.
            if offset + std::mem::size_of::<T>() > self.size {
                return Err(Error::InvalidAddress);
            }
            std::ptr::write_volatile(&mut self.as_mut_slice()[offset..] as *mut _ as *mut T, val);
            Ok(())
        }
    }

    /// Reads on object from the memory region at the given offset.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// # Examples
    /// * Read a u64 written to offset 32.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 32);
    ///     assert!(res.is_ok());
    ///     let num: u64 = mem_map.read_obj(32).unwrap();
    ///     assert_eq!(55, num);
    /// ```
    pub fn read_obj<T: Copy>(&self, offset: usize) -> Result<T> {
        if offset + std::mem::size_of::<T>() > self.size {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // This is safe because by definition Copy types can have their bits
            // set arbitrarily and still be valid.
            Ok(std::ptr::read_volatile(&self.as_slice()[offset..] as *const _ as *const T))
        }
    }

    /// Reads data from a readable object like a File and writes it to guest memory.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use sys_util::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       mem_map.read_to_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 =  mem_map.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory<F>(&self, mem_offset: usize, src: &mut F, count: usize) -> Result<()>
        where F: Read
    {
        let mem_end = mem_offset + count;
        if mem_end > self.size() {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // It is safe to overwrite the volatile memory.  Acessing the guest
            // memory as a mutable slice is OK because nothing assumes another
            // thread won't change what is loaded.
            let mut dst = &mut self.as_mut_slice()[mem_offset..mem_end];
            if src.read_exact(dst).is_err() {
                return Err(Error::ReadFromSource);
            }
        }
        Ok(())
    }

    /// Writes data from memory to a writable object.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use sys_util::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       mem_map.write_from_memory(32, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory<F>(&self, mem_offset: usize, dst: &mut F, count: usize) -> Result<()>
        where F: Write
    {
        let mem_end = match mem_offset.checked_add(count) {
            None => return Err(Error::InvalidAddress),
            Some(m) => m,
        };
        if mem_end > self.size() {
            return Err(Error::InvalidAddress);
        }
        unsafe {
            // It is safe to read from volatile memory.  Acessing the guest
            // memory as a slice is OK because nothing assumes another thread
            // won't change what is loaded.
            let src = &self.as_mut_slice()[mem_offset..mem_end];
            if dst.write_all(src).is_err() {
                return Err(Error::ReadFromSource);
            }
        }
        Ok(())
    }

    unsafe fn as_slice(&self) -> &[u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts(self.addr, self.size)
    }

    unsafe fn as_mut_slice(&self) -> &mut [u8] {
        // This is safe because we mapped the area at addr ourselves, so this slice will not
        // overflow. However, it is possible to alias.
        std::slice::from_raw_parts_mut(self.addr, self.size)
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_map() {
        let m = MemoryMapping::new(1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn test_write_past_end() {
        let m = MemoryMapping::new(5).unwrap();
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }
}

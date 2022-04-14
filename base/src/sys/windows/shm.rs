// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;

use super::{MemoryMapping, RawDescriptor, Result};
use crate::descriptor::{AsRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use libc::EINVAL;
use std::io::{
    Error, ErrorKind, Read, Seek, SeekFrom, Write, {self},
};

#[path = "win/shm.rs"]
mod shm_platform;
pub use shm_platform::*;

/// A shared memory file descriptor and its size.
pub struct SharedMemory {
    pub descriptor: SafeDescriptor,
    pub size: u64,

    // Elements used internally to perform File-like operations on this Shared Memory
    pub mapping: MemoryMapping,
    pub cursor: usize,
}

impl SharedMemory {
    /// Convenience function for `SharedMemory::new` that is always named and accepts a wide variety
    /// of string-like types.
    ///
    /// Note that the given name may not have NUL characters anywhere in it, or this will return an
    /// error.
    pub fn named<T: Into<Vec<u8>>>(name: T, size: u64) -> Result<SharedMemory> {
        SharedMemory::new(
            Some(&CString::new(name).map_err(|_| super::Error::new(EINVAL))?),
            size,
        )
    }

    /// Convenience function for `SharedMemory::new` that has an arbitrary and unspecified name.
    pub fn anon(size: u64) -> Result<SharedMemory> {
        SharedMemory::new(None, size)
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// USE THIS CAUTIOUSLY. The returned handle is not a file handle and cannot be
/// used as if it were one. It is a handle to a the associated file mapping object
/// and should only be used for memory-mapping the file view.
impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.descriptor.into_raw_descriptor()
    }
}

impl Read for SharedMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = match self.mapping.read_slice(buf, self.cursor) {
            Ok(result) => result,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Unable to read from shared memory: {}", e),
                ));
            }
        };
        let size_read = result;
        self.cursor += size_read;
        Ok(size_read)
    }
}

impl Write for SharedMemory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = match self.mapping.write_slice(buf, self.cursor) {
            Ok(result) => result,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Unable to write to shared memory: {}", e),
                ));
            }
        };
        let size_written = result;
        self.cursor += size_written;
        Ok(size_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffering is used, no flushing required
        Ok(())
    }
}

impl Seek for SharedMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_cursor: i64 = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => self.size as i64 + offset,
            SeekFrom::Current(offset) => self.cursor as i64 + offset,
        };

        if new_cursor < 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Cannot seek to a negative value",
            ));
        }

        self.cursor = new_cursor as usize;
        Ok(self.cursor as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn named() {
        const TEST_NAME: &str = "Name McCool Person";
        SharedMemory::named(TEST_NAME, 1028).expect("failed to create shared memory");
    }

    #[test]
    fn new_sized() {
        let shm = SharedMemory::anon(1028).expect("Failed to create named shared memory");
        assert_eq!(shm.size(), 1028);
    }

    #[test]
    fn new_named() {
        let name = "very unique name";
        let cname = CString::new(name).unwrap();
        SharedMemory::new(Some(&cname), 16).expect("failed to create shared memory");
    }
}

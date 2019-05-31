// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::io::AsRawFd;

use data_model::VolatileSlice;

use libc::{c_void, read, write};

/// A trait for flushing the contents of a file to disk.
/// This is equivalent to File's `sync_all` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSync {
    // Flush buffers related to this file to disk.
    fn fsync(&mut self) -> Result<()>;
}

impl FileSync for File {
    fn fsync(&mut self) -> Result<()> {
        self.sync_all()
    }
}

/// A trait for setting the size of a file.
/// This is equivalent to File's `set_len` method, but
/// wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileSetLen {
    // Set the size of this file.
    // This is the moral equivalent of `ftruncate()`.
    fn set_len(&self, _len: u64) -> Result<()>;
}

impl FileSetLen for File {
    fn set_len(&self, len: u64) -> Result<()> {
        File::set_len(self, len)
    }
}

/// A trait similar to `Read` and `Write`, but uses volatile memory as buffers.
pub trait FileReadWriteVolatile {
    /// Read bytes from this file into the given slice, returning the number of bytes read on
    /// success.
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Reads bytes from this into the given slice until all bytes in the slice are written, or an
    /// error is returned.
    fn read_exact_volatile(&mut self, mut slice: VolatileSlice) -> Result<()> {
        while slice.size() > 0 {
            let bytes_read = self.read_volatile(slice)?;
            if bytes_read == 0 {
                return Err(Error::from(ErrorKind::UnexpectedEof));
            }
            // Will panic if read_volatile read more bytes than we gave it, which would be worthy of
            // a panic.
            slice = slice.offset(bytes_read as u64).unwrap();
        }
        Ok(())
    }

    /// Write bytes from the slice to the given file, returning the number of bytes written on
    /// success.
    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Write bytes from the slice to the given file until all the bytes from the slice have been
    /// written, or an error is returned.
    fn write_all_volatile(&mut self, mut slice: VolatileSlice) -> Result<()> {
        while slice.size() > 0 {
            let bytes_written = self.write_volatile(slice)?;
            if bytes_written == 0 {
                return Err(Error::from(ErrorKind::WriteZero));
            }
            // Will panic if read_volatile read more bytes than we gave it, which would be worthy of
            // a panic.
            slice = slice.offset(bytes_written as u64).unwrap();
        }
        Ok(())
    }
}

impl FileReadWriteVolatile for File {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        // Safe because only bytes inside the slice are accessed and the kernel is expected to
        // handle arbitrary memory for I/O.
        let ret = unsafe {
            read(
                self.as_raw_fd(),
                slice.as_ptr() as *mut c_void,
                slice.size() as usize,
            )
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(Error::last_os_error())
        }
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        // Safe because only bytes inside the slice are accessed and the kernel is expected to
        // handle arbitrary memory for I/O.
        let ret = unsafe {
            write(
                self.as_raw_fd(),
                slice.as_ptr() as *const c_void,
                slice.size() as usize,
            )
        };
        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(Error::last_os_error())
        }
    }
}

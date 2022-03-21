// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    fs::File,
    io::{Error, ErrorKind, Result},
    os::unix::{
        io::{AsRawFd, RawFd},
        net::UnixStream,
    },
};

use data_model::VolatileSlice;

use super::{fallocate, FallocateMode};

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

/// A trait for getting the size of a file.
/// This is equivalent to File's metadata().len() method,
/// but wrapped in a trait so that it can be implemented for
/// other types.
pub trait FileGetLen {
    /// Get the current length of the file in bytes.
    fn get_len(&self) -> Result<u64>;
}

impl FileGetLen for File {
    fn get_len(&self) -> Result<u64> {
        Ok(self.metadata()?.len())
    }
}

/// A trait for allocating disk space in a sparse file.
/// This is equivalent to fallocate() with no special flags.
pub trait FileAllocate {
    /// Allocate storage for the region of the file starting at `offset` and extending `len` bytes.
    fn allocate(&mut self, offset: u64, len: u64) -> Result<()>;
}

impl FileAllocate for File {
    fn allocate(&mut self, offset: u64, len: u64) -> Result<()> {
        fallocate(self, FallocateMode::Allocate, true, offset, len)
            .map_err(|e| Error::from_raw_os_error(e.errno()))
    }
}

/// A trait similar to `Read` and `Write`, but uses volatile memory as buffers.
pub trait FileReadWriteVolatile {
    /// Read bytes from this file into the given slice, returning the number of bytes read on
    /// success.
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Like `read_volatile`, except it reads to a slice of buffers. Data is copied to fill each
    /// buffer in order, with the final buffer written to possibly being only partially filled. This
    /// method must behave as a single call to `read_volatile` with the buffers concatenated would.
    /// The default implementation calls `read_volatile` with either the first nonempty buffer
    /// provided, or returns `Ok(0)` if none exists.
    fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        bufs.iter()
            .find(|b| b.size() > 0)
            .map(|&b| self.read_volatile(b))
            .unwrap_or(Ok(0))
    }

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
            slice = slice.offset(bytes_read).unwrap();
        }
        Ok(())
    }

    /// Write bytes from the slice to the given file, returning the number of bytes written on
    /// success.
    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize>;

    /// Like `write_volatile`, except that it writes from a slice of buffers. Data is copied from
    /// each buffer in order, with the final buffer read from possibly being only partially
    /// consumed. This method must behave as a call to `write_volatile` with the buffers
    /// concatenated would. The default implementation calls `write_volatile` with either the first
    /// nonempty buffer provided, or returns `Ok(0)` if none exists.
    fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        bufs.iter()
            .find(|b| b.size() > 0)
            .map(|&b| self.write_volatile(b))
            .unwrap_or(Ok(0))
    }

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
            slice = slice.offset(bytes_written).unwrap();
        }
        Ok(())
    }
}

impl<'a, T: FileReadWriteVolatile + ?Sized> FileReadWriteVolatile for &'a mut T {
    fn read_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        (**self).read_volatile(slice)
    }

    fn read_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        (**self).read_vectored_volatile(bufs)
    }

    fn read_exact_volatile(&mut self, slice: VolatileSlice) -> Result<()> {
        (**self).read_exact_volatile(slice)
    }

    fn write_volatile(&mut self, slice: VolatileSlice) -> Result<usize> {
        (**self).write_volatile(slice)
    }

    fn write_vectored_volatile(&mut self, bufs: &[VolatileSlice]) -> Result<usize> {
        (**self).write_vectored_volatile(bufs)
    }

    fn write_all_volatile(&mut self, slice: VolatileSlice) -> Result<()> {
        (**self).write_all_volatile(slice)
    }
}

/// A trait similar to the unix `ReadExt` and `WriteExt` traits, but for volatile memory.
pub trait FileReadWriteAtVolatile {
    /// Reads bytes from this file at `offset` into the given slice, returning the number of bytes
    /// read on success.
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize>;

    /// Like `read_at_volatile`, except it reads to a slice of buffers. Data is copied to fill each
    /// buffer in order, with the final buffer written to possibly being only partially filled. This
    /// method must behave as a single call to `read_at_volatile` with the buffers concatenated
    /// would. The default implementation calls `read_at_volatile` with either the first nonempty
    /// buffer provided, or returns `Ok(0)` if none exists.
    fn read_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        if let Some(&slice) = bufs.first() {
            self.read_at_volatile(slice, offset)
        } else {
            Ok(0)
        }
    }

    /// Reads bytes from this file at `offset` into the given slice until all bytes in the slice are
    /// read, or an error is returned.
    fn read_exact_at_volatile(&mut self, mut slice: VolatileSlice, mut offset: u64) -> Result<()> {
        while slice.size() > 0 {
            match self.read_at_volatile(slice, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    slice = slice.offset(n).unwrap();
                    offset = offset.checked_add(n as u64).unwrap();
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes bytes from this file at `offset` into the given slice, returning the number of bytes
    /// written on success.
    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize>;

    /// Like `write_at_at_volatile`, except that it writes from a slice of buffers. Data is copied
    /// from each buffer in order, with the final buffer read from possibly being only partially
    /// consumed. This method must behave as a call to `write_at_volatile` with the buffers
    /// concatenated would. The default implementation calls `write_at_volatile` with either the
    /// first nonempty buffer provided, or returns `Ok(0)` if none exists.
    fn write_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        if let Some(&slice) = bufs.first() {
            self.write_at_volatile(slice, offset)
        } else {
            Ok(0)
        }
    }

    /// Writes bytes from this file at `offset` into the given slice until all bytes in the slice
    /// are written, or an error is returned.
    fn write_all_at_volatile(&mut self, mut slice: VolatileSlice, mut offset: u64) -> Result<()> {
        while slice.size() > 0 {
            match self.write_at_volatile(slice, offset) {
                Ok(0) => return Err(Error::from(ErrorKind::WriteZero)),
                Ok(n) => {
                    slice = slice.offset(n).unwrap();
                    offset = offset.checked_add(n as u64).unwrap();
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl<'a, T: FileReadWriteAtVolatile + ?Sized> FileReadWriteAtVolatile for &'a mut T {
    fn read_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
        (**self).read_at_volatile(slice, offset)
    }

    fn read_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        (**self).read_vectored_at_volatile(bufs, offset)
    }

    fn read_exact_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<()> {
        (**self).read_exact_at_volatile(slice, offset)
    }

    fn write_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<usize> {
        (**self).write_at_volatile(slice, offset)
    }

    fn write_vectored_at_volatile(&mut self, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        (**self).write_vectored_at_volatile(bufs, offset)
    }

    fn write_all_at_volatile(&mut self, slice: VolatileSlice, offset: u64) -> Result<()> {
        (**self).write_all_at_volatile(slice, offset)
    }
}

// This module allows the below macros to refer to $crate::platform::file_traits::lib::X and ensures other
// crates don't need to add additional crates to their Cargo.toml.
pub mod lib {
    pub use libc::{
        c_int, c_void, iovec, off64_t, pread64, preadv64, pwrite64, pwritev64, read, readv, size_t,
        write, writev,
    };

    pub use data_model::{IoBufMut, VolatileSlice};
}

#[macro_export]
macro_rules! volatile_impl {
    ($ty:ty) => {
        impl FileReadWriteVolatile for $ty {
            fn read_volatile(
                &mut self,
                slice: $crate::platform::file_traits::lib::VolatileSlice,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::read(
                        self.as_raw_fd(),
                        slice.as_mut_ptr() as *mut std::ffi::c_void,
                        slice.size() as usize,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn read_vectored_volatile(
                &mut self,
                bufs: &[$crate::platform::file_traits::lib::VolatileSlice],
            ) -> std::io::Result<usize> {
                let iobufs = $crate::platform::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::platform::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::readv(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn write_volatile(
                &mut self,
                slice: $crate::platform::file_traits::lib::VolatileSlice,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::write(
                        self.as_raw_fd(),
                        slice.as_ptr() as *const std::ffi::c_void,
                        slice.size() as usize,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn write_vectored_volatile(
                &mut self,
                bufs: &[$crate::platform::file_traits::lib::VolatileSlice],
            ) -> std::io::Result<usize> {
                let iobufs = $crate::platform::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::platform::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::writev(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
        }
    };
}

#[macro_export]
macro_rules! volatile_at_impl {
    ($ty:ty) => {
        impl FileReadWriteAtVolatile for $ty {
            fn read_at_volatile(
                &mut self,
                slice: $crate::platform::file_traits::lib::VolatileSlice,
                offset: u64,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::pread64(
                        self.as_raw_fd(),
                        slice.as_mut_ptr() as *mut std::ffi::c_void,
                        slice.size() as usize,
                        offset as $crate::platform::file_traits::lib::off64_t,
                    )
                };

                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn read_vectored_at_volatile(
                &mut self,
                bufs: &[$crate::platform::file_traits::lib::VolatileSlice],
                offset: u64,
            ) -> std::io::Result<usize> {
                let iobufs = $crate::platform::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::platform::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::preadv64(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                        offset as $crate::platform::file_traits::lib::off64_t,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn write_at_volatile(
                &mut self,
                slice: $crate::platform::file_traits::lib::VolatileSlice,
                offset: u64,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::pwrite64(
                        self.as_raw_fd(),
                        slice.as_ptr() as *const std::ffi::c_void,
                        slice.size() as usize,
                        offset as $crate::platform::file_traits::lib::off64_t,
                    )
                };

                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }

            fn write_vectored_at_volatile(
                &mut self,
                bufs: &[$crate::platform::file_traits::lib::VolatileSlice],
                offset: u64,
            ) -> std::io::Result<usize> {
                let iobufs = $crate::platform::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::platform::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::platform::file_traits::lib::pwritev64(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                        offset as $crate::platform::file_traits::lib::off64_t,
                    )
                };
                if ret >= 0 {
                    Ok(ret as usize)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
        }
    };
}

volatile_impl!(File);
volatile_at_impl!(File);
volatile_impl!(UnixStream);

/// A trait similar to `AsRawFd` but supports an arbitrary number of file descriptors.
pub trait AsRawFds {
    fn as_raw_fds(&self) -> Vec<RawFd>;
}

impl<T> AsRawFds for T
where
    T: AsRawFd,
{
    fn as_raw_fds(&self) -> Vec<RawFd> {
        vec![self.as_raw_fd()]
    }
}

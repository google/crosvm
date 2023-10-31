// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error;
use std::io::Result;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

use super::fallocate;
use super::FallocateMode;
use crate::FileAllocate;
use crate::FileReadWriteAtVolatile;
use crate::FileReadWriteVolatile;

impl FileAllocate for File {
    fn allocate(&mut self, offset: u64, len: u64) -> Result<()> {
        fallocate(self, FallocateMode::Allocate, true, offset, len)
            .map_err(|e| Error::from_raw_os_error(e.errno()))
    }
}

// This module allows the below macros to refer to $crate::linux::file_traits::lib::X and ensures other
// crates don't need to add additional crates to their Cargo.toml.
pub mod lib {
    pub use data_model::IoBufMut;
    pub use data_model::VolatileSlice;
    pub use libc::c_int;
    pub use libc::c_void;
    pub use libc::iovec;
    pub use libc::off64_t;
    pub use libc::pread64;
    pub use libc::preadv64;
    pub use libc::pwrite64;
    pub use libc::pwritev64;
    pub use libc::read;
    pub use libc::readv;
    pub use libc::size_t;
    pub use libc::write;
    pub use libc::writev;
}

#[macro_export]
macro_rules! volatile_impl {
    ($ty:ty) => {
        impl FileReadWriteVolatile for $ty {
            fn read_volatile(
                &mut self,
                slice: $crate::linux::file_traits::lib::VolatileSlice,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::read(
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
                bufs: &[$crate::linux::file_traits::lib::VolatileSlice],
            ) -> std::io::Result<usize> {
                let iobufs = $crate::linux::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::linux::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::readv(
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
                slice: $crate::linux::file_traits::lib::VolatileSlice,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::write(
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
                bufs: &[$crate::linux::file_traits::lib::VolatileSlice],
            ) -> std::io::Result<usize> {
                let iobufs = $crate::linux::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::linux::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::writev(
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
                slice: $crate::linux::file_traits::lib::VolatileSlice,
                offset: u64,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::pread64(
                        self.as_raw_fd(),
                        slice.as_mut_ptr() as *mut std::ffi::c_void,
                        slice.size() as usize,
                        offset as $crate::linux::file_traits::lib::off64_t,
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
                bufs: &[$crate::linux::file_traits::lib::VolatileSlice],
                offset: u64,
            ) -> std::io::Result<usize> {
                let iobufs = $crate::linux::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::linux::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::preadv64(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                        offset as $crate::linux::file_traits::lib::off64_t,
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
                slice: $crate::linux::file_traits::lib::VolatileSlice,
                offset: u64,
            ) -> std::io::Result<usize> {
                // Safe because only bytes inside the slice are accessed and the kernel is expected
                // to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::pwrite64(
                        self.as_raw_fd(),
                        slice.as_ptr() as *const std::ffi::c_void,
                        slice.size() as usize,
                        offset as $crate::linux::file_traits::lib::off64_t,
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
                bufs: &[$crate::linux::file_traits::lib::VolatileSlice],
                offset: u64,
            ) -> std::io::Result<usize> {
                let iobufs = $crate::linux::file_traits::lib::VolatileSlice::as_iobufs(bufs);
                let iovecs = $crate::linux::file_traits::lib::IoBufMut::as_iobufs(iobufs);

                if iovecs.is_empty() {
                    return Ok(0);
                }

                // Safe because only bytes inside the buffers are accessed and the kernel is
                // expected to handle arbitrary memory for I/O.
                let ret = unsafe {
                    $crate::linux::file_traits::lib::pwritev64(
                        self.as_raw_fd(),
                        iovecs.as_ptr(),
                        iovecs.len() as std::os::raw::c_int,
                        offset as $crate::linux::file_traits::lib::off64_t,
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

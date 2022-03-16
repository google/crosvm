// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    ffi::{CStr, CString},
    fs::{read_link, File},
    io::{
        Read, Seek, SeekFrom, Write, {self},
    },
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
};

use libc::{
    c_char, c_int, c_long, c_uint, close, fcntl, ftruncate64, off64_t, syscall, SYS_memfd_create,
    EINVAL, F_ADD_SEALS, F_GET_SEALS, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK,
    F_SEAL_WRITE, MFD_ALLOW_SEALING, {self},
};
use serde::{Deserialize, Serialize};

use super::{errno_result, Error, Result};

/// A shared memory file descriptor and its size.
#[derive(Serialize, Deserialize)]
pub struct SharedMemory {
    #[serde(with = "super::with_as_descriptor")]
    fd: File,
    size: u64,
}

// from <sys/memfd.h>
const MFD_CLOEXEC: c_uint = 0x0001;

unsafe fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    syscall(SYS_memfd_create as c_long, name, flags) as c_int
}

/// A set of memfd seals.
///
/// An enumeration of each bit can be found at `fcntl(2)`.
#[derive(Copy, Clone, Default)]
pub struct MemfdSeals(i32);

impl MemfdSeals {
    /// Returns an empty set of memfd seals.
    #[inline]
    pub fn new() -> MemfdSeals {
        MemfdSeals(0)
    }

    /// Gets the raw bitmask of seals enumerated in `fcntl(2)`.
    #[inline]
    pub fn bitmask(self) -> i32 {
        self.0
    }

    /// True if the grow seal bit is present.
    #[inline]
    pub fn grow_seal(self) -> bool {
        self.0 & F_SEAL_GROW != 0
    }

    /// Sets the grow seal bit.
    #[inline]
    pub fn set_grow_seal(&mut self) {
        self.0 |= F_SEAL_GROW;
    }

    /// True if the shrink seal bit is present.
    #[inline]
    pub fn shrink_seal(self) -> bool {
        self.0 & F_SEAL_SHRINK != 0
    }

    /// Sets the shrink seal bit.
    #[inline]
    pub fn set_shrink_seal(&mut self) {
        self.0 |= F_SEAL_SHRINK;
    }

    /// True if the write seal bit is present.
    #[inline]
    pub fn write_seal(self) -> bool {
        self.0 & F_SEAL_WRITE != 0
    }

    /// Sets the write seal bit.
    #[inline]
    pub fn set_write_seal(&mut self) {
        self.0 |= F_SEAL_WRITE;
    }

    /// True if the future write seal bit is present.
    #[inline]
    pub fn future_write_seal(self) -> bool {
        self.0 & F_SEAL_FUTURE_WRITE != 0
    }

    /// Sets the future write seal bit.
    #[inline]
    pub fn set_future_write_seal(&mut self) {
        self.0 |= F_SEAL_FUTURE_WRITE;
    }

    /// True of the seal seal bit is present.
    #[inline]
    pub fn seal_seal(self) -> bool {
        self.0 & F_SEAL_SEAL != 0
    }

    /// Sets the seal seal bit.
    #[inline]
    pub fn set_seal_seal(&mut self) {
        self.0 |= F_SEAL_SEAL;
    }
}

impl SharedMemory {
    /// Convenience function for `SharedMemory::new` that is always named and accepts a wide variety
    /// of string-like types.
    ///
    /// Note that the given name may not have NUL characters anywhere in it, or this will return an
    /// error.
    pub fn named<T: Into<Vec<u8>>>(name: T) -> Result<SharedMemory> {
        Self::new(Some(&CString::new(name).map_err(|_| Error::new(EINVAL))?))
    }

    /// Convenience function for `SharedMemory::new` that has an arbitrary and unspecified name.
    pub fn anon() -> Result<SharedMemory> {
        Self::new(None)
    }

    /// Creates a new shared memory file descriptor with zero size.
    ///
    /// If a name is given, it will appear in `/proc/self/fd/<shm fd>` for the purposes of
    /// debugging. The name does not need to be unique.
    ///
    /// The file descriptor is opened with the close on exec flag and allows memfd sealing.
    pub fn new(name: Option<&CStr>) -> Result<SharedMemory> {
        let shm_name = name
            .map(|n| n.as_ptr())
            .unwrap_or(b"/crosvm_shm\0".as_ptr() as *const c_char);
        // The following are safe because we give a valid C string and check the
        // results of the memfd_create call.
        let fd = unsafe { memfd_create(shm_name, MFD_CLOEXEC | MFD_ALLOW_SEALING) };
        if fd < 0 {
            return errno_result();
        }

        let file = unsafe { File::from_raw_fd(fd) };

        Ok(SharedMemory { fd: file, size: 0 })
    }

    /// Constructs a `SharedMemory` instance from a `File` that represents shared memory.
    ///
    /// The size of the resulting shared memory will be determined using `File::seek`. If the given
    /// file's size can not be determined this way, this will return an error.
    pub fn from_file(mut file: File) -> Result<SharedMemory> {
        let file_size = file.seek(SeekFrom::End(0))?;
        Ok(SharedMemory {
            fd: file,
            size: file_size as u64,
        })
    }

    /// Gets the memfd seals that have already been added to this.
    ///
    /// This may fail if this instance was not constructed from a memfd.
    pub fn get_seals(&self) -> Result<MemfdSeals> {
        let ret = unsafe { fcntl(self.fd.as_raw_fd(), F_GET_SEALS) };
        if ret < 0 {
            return errno_result();
        }
        Ok(MemfdSeals(ret))
    }

    /// Adds the given set of memfd seals.
    ///
    /// This may fail if this instance was not constructed from a memfd with sealing allowed or if
    /// the seal seal (`F_SEAL_SEAL`) bit was already added.
    pub fn add_seals(&mut self, seals: MemfdSeals) -> Result<()> {
        let ret = unsafe { fcntl(self.fd.as_raw_fd(), F_ADD_SEALS, seals) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor..
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Sets the size in bytes of the shared memory.
    ///
    /// Note that if some process has already mapped this shared memory and the new size is smaller,
    /// that process may get signaled with SIGBUS if they access any page past the new size.
    pub fn set_size(&mut self, size: u64) -> Result<()> {
        let ret = unsafe { ftruncate64(self.fd.as_raw_fd(), size as off64_t) };
        if ret < 0 {
            return errno_result();
        }
        self.size = size;
        Ok(())
    }

    /// Reads the name from the underlying file as a `String`.
    ///
    /// If the underlying file was not created with `SharedMemory::new` or with `memfd_create`, the
    /// results are undefined. Because this returns a `String`, the name's bytes are interpreted as
    /// utf-8.
    pub fn read_name(&self) -> Result<String> {
        let fd_path = format!("/proc/self/fd/{}", self.as_raw_fd());
        let link_name = read_link(fd_path)?;
        link_name
            .to_str()
            .map(|s| {
                s.trim_start_matches("/memfd:")
                    .trim_end_matches(" (deleted)")
                    .to_owned()
            })
            .ok_or_else(|| Error::new(EINVAL))
    }
}

impl Read for SharedMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }
}

impl Read for &SharedMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.fd).read(buf)
    }
}

impl Write for SharedMemory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
}

impl Write for &SharedMemory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.fd).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.fd).flush()
    }
}

impl Seek for SharedMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
    }
}

impl Seek for &SharedMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (&self.fd).seek(pos)
    }
}

impl AsRawFd for SharedMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsRawFd for &SharedMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for SharedMemory {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl From<SharedMemory> for File {
    fn from(s: SharedMemory) -> File {
        s.fd
    }
}

/// Checks if the kernel we are running on has memfd_create. It was introduced in 3.17.
/// Only to be used from tests to prevent running on ancient kernels that won't
/// support the functionality anyways.
pub fn kernel_has_memfd() -> bool {
    unsafe {
        let fd = memfd_create(b"/test_memfd_create\0".as_ptr() as *const c_char, 0);
        if fd < 0 {
            if Error::last().errno() == libc::ENOSYS {
                return false;
            }
            return true;
        }
        close(fd);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    use data_model::VolatileMemory;

    use super::super::MemoryMapping;

    #[test]
    fn named() {
        if !kernel_has_memfd() {
            return;
        }
        const TEST_NAME: &str = "Name McCool Person";
        let shm = SharedMemory::named(TEST_NAME).expect("failed to create shared memory");
        assert_eq!(shm.read_name(), Ok(TEST_NAME.to_owned()));
    }

    #[test]
    fn anon() {
        if !kernel_has_memfd() {
            return;
        }
        SharedMemory::anon().expect("failed to create shared memory");
    }

    #[test]
    fn new() {
        if !kernel_has_memfd() {
            return;
        }
        let shm = SharedMemory::anon().expect("failed to create shared memory");
        assert_eq!(shm.size(), 0);
    }

    #[test]
    fn new_sized() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        shm.set_size(1024)
            .expect("failed to set shared memory size");
        assert_eq!(shm.size(), 1024);
    }

    #[test]
    fn new_huge() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        shm.set_size(0x7fff_ffff_ffff_ffff)
            .expect("failed to set shared memory size");
        assert_eq!(shm.size(), 0x7fff_ffff_ffff_ffff);
    }

    #[test]
    fn new_too_huge() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        shm.set_size(0x8000_0000_0000_0000).unwrap_err();
        assert_eq!(shm.size(), 0);
    }

    #[test]
    fn new_named() {
        if !kernel_has_memfd() {
            return;
        }
        let name = "very unique name";
        let cname = CString::new(name).unwrap();
        let shm = SharedMemory::new(Some(&cname)).expect("failed to create shared memory");
        assert_eq!(shm.read_name(), Ok(name.to_owned()));
    }

    #[test]
    fn new_sealed() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        let mut seals = shm.get_seals().expect("failed to get seals");
        assert_eq!(seals.bitmask(), 0);
        seals.set_seal_seal();
        shm.add_seals(seals).expect("failed to add seals");
        seals = shm.get_seals().expect("failed to get seals");
        assert!(seals.seal_seal());
        // Adding more seals should be rejected by the kernel.
        shm.add_seals(seals).unwrap_err();
    }

    #[test]
    fn mmap_page() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        shm.set_size(4096)
            .expect("failed to set shared memory size");

        let mmap1 =
            MemoryMapping::from_fd(&shm, shm.size() as usize).expect("failed to map shared memory");
        let mmap2 =
            MemoryMapping::from_fd(&shm, shm.size() as usize).expect("failed to map shared memory");

        assert_ne!(
            mmap1.get_slice(0, 1).unwrap().as_ptr(),
            mmap2.get_slice(0, 1).unwrap().as_ptr()
        );

        mmap1
            .get_slice(0, 4096)
            .expect("failed to get mmap slice")
            .write_bytes(0x45);

        for i in 0..4096 {
            assert_eq!(mmap2.get_ref::<u8>(i).unwrap().load(), 0x45u8);
        }
    }

    #[test]
    fn mmap_page_offset() {
        if !kernel_has_memfd() {
            return;
        }
        let mut shm = SharedMemory::anon().expect("failed to create shared memory");
        shm.set_size(8092)
            .expect("failed to set shared memory size");

        let mmap1 = MemoryMapping::from_fd_offset(&shm, shm.size() as usize, 4096)
            .expect("failed to map shared memory");
        let mmap2 =
            MemoryMapping::from_fd(&shm, shm.size() as usize).expect("failed to map shared memory");

        mmap1
            .get_slice(0, 4096)
            .expect("failed to get mmap slice")
            .write_bytes(0x45);

        for i in 0..4096 {
            assert_eq!(mmap2.get_ref::<u8>(i).unwrap().load(), 0);
        }
        for i in 4096..8092 {
            assert_eq!(mmap2.get_ref::<u8>(i).unwrap().load(), 0x45u8);
        }
    }
}

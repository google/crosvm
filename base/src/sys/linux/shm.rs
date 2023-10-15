// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::close;
use libc::fcntl;
use libc::ftruncate64;
use libc::off64_t;
use libc::syscall;
use libc::SYS_memfd_create;
use libc::F_ADD_SEALS;
use libc::F_GET_SEALS;
use libc::F_SEAL_FUTURE_WRITE;
use libc::F_SEAL_GROW;
use libc::F_SEAL_SEAL;
use libc::F_SEAL_SHRINK;
use libc::F_SEAL_WRITE;
use libc::MFD_ALLOW_SEALING;
use once_cell::sync::Lazy;

use crate::errno_result;
use crate::shm::PlatformSharedMemory;
use crate::trace;
use crate::AsRawDescriptor;
use crate::FromRawDescriptor;
use crate::Result;
use crate::SafeDescriptor;
use crate::SharedMemory;

// from <sys/memfd.h>
const MFD_CLOEXEC: c_uint = 0x0001;
const MFD_NOEXEC_SEAL: c_uint = 0x0008;

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

static MFD_NOEXEC_SEAL_SUPPORTED: Lazy<bool> = Lazy::new(|| {
    // SAFETY: We pass a valid zero-terminated C string and check the result.
    let fd = unsafe {
        // The memfd name used here does not need to be unique, since duplicates are allowed and
        // will not cause failures.
        memfd_create(
            b"MFD_NOEXEC_SEAL_test\0".as_ptr() as *const c_char,
            MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL,
        )
    };
    if fd < 0 {
        trace!("MFD_NOEXEC_SEAL is not supported");
        false
    } else {
        trace!("MFD_NOEXEC_SEAL is supported");
        // SAFETY: We know `fd` is a valid file descriptor owned by us.
        unsafe {
            close(fd);
        }
        true
    }
});

impl PlatformSharedMemory for SharedMemory {
    /// Creates a new shared memory file descriptor with the specified `size` in bytes.
    ///
    /// `name` will appear in `/proc/self/fd/<shm fd>` for the purposes of debugging. The name does
    /// not need to be unique.
    ///
    /// The file descriptor is opened with the close on exec flag and allows memfd sealing.
    ///
    /// If the `MFD_NOEXEC_SEAL` flag is supported, the resulting file will also be created with a
    /// non-executable file mode (in other words, it cannot be passed to the `exec` family of system
    /// calls).
    fn new(debug_name: &CStr, size: u64) -> Result<SharedMemory> {
        let mut flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
        if *MFD_NOEXEC_SEAL_SUPPORTED {
            flags |= MFD_NOEXEC_SEAL;
        }

        let shm_name = debug_name.as_ptr() as *const c_char;
        // The following are safe because we give a valid C string and check the
        // results of the memfd_create call.
        let fd = unsafe { memfd_create(shm_name, flags) };
        if fd < 0 {
            return errno_result();
        }
        let descriptor = unsafe { SafeDescriptor::from_raw_descriptor(fd) };

        // Set the size of the memfd.
        let ret = unsafe { ftruncate64(descriptor.as_raw_descriptor(), size as off64_t) };
        if ret < 0 {
            return errno_result();
        }

        Ok(SharedMemory { descriptor, size })
    }

    /// Creates a SharedMemory instance from a SafeDescriptor owning a reference to a
    /// shared memory descriptor. Ownership of the underlying descriptor is transferred to the
    /// new SharedMemory object.
    fn from_safe_descriptor(descriptor: SafeDescriptor, size: u64) -> Result<SharedMemory> {
        Ok(SharedMemory { descriptor, size })
    }
}

pub trait SharedMemoryLinux {
    /// Constructs a `SharedMemory` instance from a `File` that represents shared memory.
    ///
    /// The size of the resulting shared memory will be determined using `File::seek`. If the given
    /// file's size can not be determined this way, this will return an error.
    fn from_file(file: File) -> Result<SharedMemory>;

    /// Gets the memfd seals that have already been added to this.
    ///
    /// This may fail if this instance was not constructed from a memfd.
    fn get_seals(&self) -> Result<MemfdSeals>;

    /// Adds the given set of memfd seals.
    ///
    /// This may fail if this instance was not constructed from a memfd with sealing allowed or if
    /// the seal seal (`F_SEAL_SEAL`) bit was already added.
    fn add_seals(&mut self, seals: MemfdSeals) -> Result<()>;
}

impl SharedMemoryLinux for SharedMemory {
    fn from_file(mut file: File) -> Result<SharedMemory> {
        let file_size = file.seek(SeekFrom::End(0))?;
        Ok(SharedMemory {
            descriptor: file.into(),
            size: file_size,
        })
    }

    fn get_seals(&self) -> Result<MemfdSeals> {
        let ret = unsafe { fcntl(self.descriptor.as_raw_descriptor(), F_GET_SEALS) };
        if ret < 0 {
            return errno_result();
        }
        Ok(MemfdSeals(ret))
    }

    fn add_seals(&mut self, seals: MemfdSeals) -> Result<()> {
        let ret = unsafe { fcntl(self.descriptor.as_raw_descriptor(), F_ADD_SEALS, seals) };
        if ret < 0 {
            return errno_result();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::read_link;

    use data_model::VolatileMemory;
    use libc::EINVAL;

    use crate::linux::SharedMemoryLinux;
    use crate::pagesize;
    use crate::AsRawDescriptor;
    use crate::Error;
    use crate::MemoryMappingBuilder;
    use crate::Result;
    use crate::SharedMemory;

    /// Reads the name from the underlying file as a `String`.
    ///
    /// If the underlying file was not created with `SharedMemory::new` or with `memfd_create`, the
    /// results are undefined. Because this returns a `String`, the name's bytes are interpreted as
    /// utf-8.
    fn read_name(shm: &SharedMemory) -> Result<String> {
        let fd_path = format!("/proc/self/fd/{}", shm.as_raw_descriptor());
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

    #[test]
    fn new() {
        const TEST_NAME: &str = "Name McCool Person";
        let shm = SharedMemory::new(TEST_NAME, 0).expect("failed to create shared memory");
        assert_eq!(read_name(&shm), Ok(TEST_NAME.to_owned()));
    }

    #[test]
    fn new_huge() {
        let shm = SharedMemory::new("test", 0x7fff_ffff_ffff_ffff)
            .expect("failed to create shared memory");
        assert_eq!(shm.size(), 0x7fff_ffff_ffff_ffff);
    }

    #[test]
    fn new_sealed() {
        let mut shm = SharedMemory::new("test", 0).expect("failed to create shared memory");
        let mut seals = shm.get_seals().expect("failed to get seals");
        assert!(!seals.seal_seal());
        seals.set_seal_seal();
        shm.add_seals(seals).expect("failed to add seals");
        seals = shm.get_seals().expect("failed to get seals");
        assert!(seals.seal_seal());
        // Adding more seals should be rejected by the kernel.
        shm.add_seals(seals).unwrap_err();
    }

    #[test]
    fn mmap_page() {
        let shm = SharedMemory::new("test", 4096).expect("failed to create shared memory");

        let mmap1 = MemoryMappingBuilder::new(shm.size() as usize)
            .from_shared_memory(&shm)
            .build()
            .expect("failed to map shared memory");
        let mmap2 = MemoryMappingBuilder::new(shm.size() as usize)
            .from_shared_memory(&shm)
            .build()
            .expect("failed to map shared memory");

        assert_ne!(
            mmap1.get_slice(0, 1).unwrap().as_ptr(),
            mmap2.get_slice(0, 1).unwrap().as_ptr()
        );

        mmap1
            .get_slice(0, 4096)
            .expect("failed to get mmap slice")
            .write_bytes(0x45);

        for i in 0..4096 {
            assert_eq!(mmap2.read_obj::<u8>(i).unwrap(), 0x45u8);
        }
    }

    #[test]
    fn mmap_page_offset() {
        let shm = SharedMemory::new("test", 2 * pagesize() as u64)
            .expect("failed to create shared memory");

        let mmap1 = MemoryMappingBuilder::new(shm.size() as usize)
            .from_shared_memory(&shm)
            .offset(pagesize() as u64)
            .build()
            .expect("failed to map shared memory");
        let mmap2 = MemoryMappingBuilder::new(shm.size() as usize)
            .from_shared_memory(&shm)
            .build()
            .expect("failed to map shared memory");

        mmap1
            .get_slice(0, pagesize())
            .expect("failed to get mmap slice")
            .write_bytes(0x45);

        for i in 0..pagesize() {
            assert_eq!(mmap2.read_obj::<u8>(i).unwrap(), 0);
        }
        for i in pagesize()..(2 * pagesize()) {
            assert_eq!(mmap2.read_obj::<u8>(i).unwrap(), 0x45u8);
        }
    }
}

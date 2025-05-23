// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::ffi::CStr;
use std::os::fd::AsRawFd;
use std::os::fd::IntoRawFd;
use std::os::unix::io::OwnedFd;

use rustix::fs::ftruncate;
use rustix::fs::memfd_create;
use rustix::fs::MemfdFlags;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::MesaResult;
use crate::RawDescriptor;

pub struct SharedMemory {
    fd: OwnedFd,
    size: u64,
}

impl SharedMemory {
    /// Creates a new shared memory file descriptor with zero size.
    ///
    /// If a name is given, it will appear in `/proc/self/fd/<shm fd>` for the purposes of
    /// debugging. The name does not need to be unique.
    ///
    /// The file descriptor is opened with the close on exec flag and allows memfd sealing.
    pub fn new(debug_name: &CStr, size: u64) -> MesaResult<SharedMemory> {
        let fd = memfd_create(debug_name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)?;

        ftruncate(&fd, size)?;

        Ok(SharedMemory { fd, size })
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor..
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.fd.as_raw_fd()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.fd.into_raw_fd()
    }
}

pub fn page_size() -> MesaResult<u64> {
    // TODO: Once all platforms support it, use rustix page_size() function everywhere.
    Ok(rustix::param::page_size() as _)
}

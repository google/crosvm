// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides wrapper of userfaultfd crate for vmm-swap feature.

#![deny(missing_docs)]

use std::convert::From;
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::FromRawFd;

use base::AsRawDescriptor;
use base::FromRawDescriptor;
use base::RawDescriptor;
pub use userfaultfd::Error as UffdError;
pub use userfaultfd::Event as UffdEvent;
use userfaultfd::FeatureFlags;
use userfaultfd::IoctlFlags;
use userfaultfd::Result;
use userfaultfd::Uffd;
use userfaultfd::UffdBuilder;

/// Wrapper for [`userfaultfd::Uffd`] to be used in the vmm-swap feature.
///
/// # Safety
///
/// The userfaultfd operations (`UFFDIO_COPY` and `UFFDIO_ZEROPAGE`) looks unsafe since it fills a
/// memory content directly. But they actually are not unsafe operation but `UFFDIO_REGISTER` should
/// be the unsafe operation for Rust memory safety.
///
/// According to [the Rust document](https://doc.rust-lang.org/nomicon/uninitialized.html),
///
/// > All runtime-allocated memory in a Rust program begins its life as uninitialized.
///
/// The userfaultfd operations actually does not change/overwrite the existing memory contents but
/// they just setup the "uninitialized" pages. If the page was already initialized, the userfaultfd
/// operations fail and return EEXIST error (which is not documented unfortunately). So they
/// originally does not affect the Rust memory safety.
///
/// The "uninitialized" page in this context has 2 patterns:
///
/// 1. pages which is never touched or,
/// 2. pages which is never touched after MADV_REMOVE
///
/// Filling the (1) pages with any contents should not affect the Rust memory safety.
///
/// Filling the (2) pages potentially may break the memory used by Rust. But the safety should be
/// examined at `MADV_REMOVE` and `UFFDIO_REGISTER` timing.
pub struct Userfaultfd {
    uffd: Uffd,
}

impl Userfaultfd {
    /// Creates a new userfaultfd.
    pub fn new() -> Result<Self> {
        let uffd = UffdBuilder::new()
            .close_on_exec(true)
            .non_blocking(true)
            .user_mode_only(false)
            .require_features(
                FeatureFlags::EVENT_FORK | FeatureFlags::MISSING_SHMEM | FeatureFlags::EVENT_REMOVE,
            )
            .create()?;
        Ok(Self { uffd })
    }

    /// Register a range of memory to the userfaultfd.
    ///
    /// After this registration, any page faults on the range will be caught by the userfaultfd.
    ///
    /// # Arguments
    ///
    /// * `addr` - the starting address of the range of memory.
    /// * `len` - the length in bytes of the range of memory.
    ///
    /// # Safety
    ///
    /// [addr, addr+len) must lie within a [MemoryMapping](base::MemoryMapping), and that mapping
    /// must live for the lifespan of the userfaultfd kernel object (which may be distinct from the
    /// `Userfaultfd` rust object in this process).
    pub unsafe fn register(&self, addr: usize, len: usize) -> Result<IoctlFlags> {
        self.uffd.register(addr as *mut libc::c_void, len)
    }

    /// Unregister a range of memory from the userfaultfd.
    ///
    /// # Arguments
    ///
    /// * `addr` - the starting address of the range of memory.
    /// * `len` - the length in bytes of the range of memory.
    pub fn unregister(&self, addr: usize, len: usize) -> Result<()> {
        self.uffd.unregister(addr as *mut libc::c_void, len)
    }

    /// Initialize page(s) and fill it with zero.
    ///
    /// # Arguments
    ///
    /// * `addr` - the starting address of the page(s) to be initialzed with zero.
    /// * `len` - the length in bytes of the page(s).
    /// * `wake` - whether or not to unblock the faulting thread.
    pub fn zero(&self, addr: usize, len: usize, wake: bool) -> Result<usize> {
        // safe because zeroing untouched pages does not break the Rust memory safety since "All
        // runtime-allocated memory in a Rust program begins its life as uninitialized."
        // https://doc.rust-lang.org/nomicon/uninitialized.html
        unsafe { self.uffd.zeropage(addr as *mut libc::c_void, len, wake) }
    }

    /// Copy the `data` to the page(s) starting from `addr`.
    ///
    /// # Arguments
    ///
    /// * `addr` - the starting address of the page(s) to be initialzed with data.
    /// * `len` - the length in bytes of the page(s).
    /// * `data` - the starting address of the content.
    /// * `wake` - whether or not to unblock the faulting thread.
    pub fn copy(&self, addr: usize, len: usize, data: *const u8, wake: bool) -> Result<usize> {
        // safe because filling untouched pages with data does not break the Rust memory safety
        // since "All runtime-allocated memory in a Rust program begins its life as uninitialized."
        // https://doc.rust-lang.org/nomicon/uninitialized.html
        unsafe {
            self.uffd.copy(
                data as *const libc::c_void,
                addr as *mut libc::c_void,
                len,
                wake,
            )
        }
    }

    /// Read an event from the userfaultfd.
    ///
    /// Return `None` immediately if no events is ready to read.
    pub fn read_event(&self) -> Result<Option<UffdEvent>> {
        self.uffd.read_event()
    }
}

impl From<Uffd> for Userfaultfd {
    fn from(uffd: Uffd) -> Self {
        Self { uffd }
    }
}

impl FromRawDescriptor for Userfaultfd {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Self::from(Uffd::from_raw_fd(descriptor))
    }
}

impl AsRawDescriptor for Userfaultfd {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.uffd.as_raw_fd()
    }
}

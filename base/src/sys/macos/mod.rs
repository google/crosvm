// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use crate::descriptor::FromRawDescriptor;
use crate::sys::unix::RawDescriptor;
use crate::unix::set_descriptor_cloexec;
use crate::unix::Pid;
use crate::MmapError;

mod event;
pub(in crate::sys::macos) mod kqueue;
mod net;
mod timer;

pub(crate) use event::PlatformEvent;
pub(in crate::sys) use libc::sendmsg;
pub(in crate::sys) use net::sockaddr_un;
pub(in crate::sys) use net::sockaddrv4_to_lib_c;
pub(in crate::sys) use net::sockaddrv6_to_lib_c;

pub fn set_thread_name(_name: &str) -> crate::errno::Result<()> {
    todo!();
}

pub fn get_cpu_affinity() -> crate::errno::Result<Vec<usize>> {
    todo!();
}

pub fn getpid() -> Pid {
    todo!();
}

pub fn open_file_or_duplicate<P: AsRef<std::path::Path>>(
    _path: P,
    _options: &std::fs::OpenOptions,
) -> crate::Result<std::fs::File> {
    todo!();
}

pub mod platform_timer_resolution {
    pub struct UnixSetTimerResolution {}
    impl crate::EnabledHighResTimer for UnixSetTimerResolution {}

    pub fn enable_high_res_timers() -> crate::Result<Box<dyn crate::EnabledHighResTimer>> {
        todo!();
    }
}

pub fn set_cpu_affinity<I: IntoIterator<Item = usize>>(_cpus: I) -> crate::errno::Result<()> {
    todo!();
}

pub struct EventContext<T: crate::EventToken> {
    p: std::marker::PhantomData<T>,
}

impl<T: crate::EventToken> EventContext<T> {
    pub fn new() -> crate::errno::Result<EventContext<T>> {
        todo!();
    }
    pub fn build_with(
        _fd_tokens: &[(&dyn crate::AsRawDescriptor, T)],
    ) -> crate::errno::Result<EventContext<T>> {
        todo!();
    }
    pub fn add_for_event(
        &self,
        _descriptor: &dyn crate::AsRawDescriptor,
        _event_type: crate::EventType,
        _token: T,
    ) -> crate::errno::Result<()> {
        todo!();
    }
    pub fn modify(
        &self,
        _fd: &dyn crate::AsRawDescriptor,
        _event_type: crate::EventType,
        _token: T,
    ) -> crate::errno::Result<()> {
        todo!();
    }
    pub fn delete(&self, _fd: &dyn crate::AsRawDescriptor) -> crate::errno::Result<()> {
        todo!();
    }
    pub fn wait(&self) -> crate::errno::Result<smallvec::SmallVec<[crate::TriggeredEvent<T>; 16]>> {
        todo!();
    }
    pub fn wait_timeout(
        &self,
        _timeout: std::time::Duration,
    ) -> crate::errno::Result<smallvec::SmallVec<[crate::TriggeredEvent<T>; 16]>> {
        todo!();
    }
}

impl<T: crate::EventToken> crate::AsRawDescriptor for EventContext<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        todo!();
    }
}

pub struct MemoryMappingArena {}

#[derive(Debug)]
pub struct MemoryMapping {}

impl MemoryMapping {
    pub fn size(&self) -> usize {
        todo!();
    }
    pub(crate) fn range_end(&self, _offset: usize, _count: usize) -> Result<usize, MmapError> {
        todo!();
    }
    pub fn msync(&self) -> Result<(), MmapError> {
        todo!();
    }
    pub fn new_protection_fixed(
        _addr: *mut u8,
        _size: usize,
        _prot: crate::Protection,
    ) -> Result<MemoryMapping, MmapError> {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn from_descriptor_offset_protection_fixed(
        _addr: *mut u8,
        _fd: &dyn crate::AsRawDescriptor,
        _size: usize,
        _offset: u64,
        _prot: crate::Protection,
    ) -> Result<MemoryMapping, MmapError> {
        todo!();
    }
}

// SAFETY: Unimplemented, always aborts
unsafe impl crate::MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        todo!();
    }
    fn size(&self) -> usize {
        todo!();
    }
}

pub mod ioctl {
    pub type IoctlNr = std::ffi::c_ulong;
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl<F: crate::AsRawDescriptor>(
        _descriptor: &F,
        _nr: IoctlNr,
    ) -> std::ffi::c_int {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl_with_val(
        _descriptor: &dyn crate::AsRawDescriptor,
        _nr: IoctlNr,
        _arg: std::ffi::c_ulong,
    ) -> std::ffi::c_int {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl_with_ref<T>(
        _descriptor: &dyn crate::AsRawDescriptor,
        _nr: IoctlNr,
        _arg: &T,
    ) -> std::ffi::c_int {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl_with_mut_ref<T>(
        _descriptor: &dyn crate::AsRawDescriptor,
        _nr: IoctlNr,
        _arg: &mut T,
    ) -> std::ffi::c_int {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl_with_ptr<T>(
        _descriptor: &dyn crate::AsRawDescriptor,
        _nr: IoctlNr,
        _arg: *const T,
    ) -> std::ffi::c_int {
        todo!();
    }
    /// # Safety
    ///
    /// unimplemented, always aborts
    pub unsafe fn ioctl_with_mut_ptr<T>(
        _descriptor: &dyn crate::AsRawDescriptor,
        _nr: IoctlNr,
        _arg: *mut T,
    ) -> std::ffi::c_int {
        todo!();
    }
}

pub fn file_punch_hole(_file: &std::fs::File, _offset: u64, _length: u64) -> std::io::Result<()> {
    todo!();
}

pub fn file_write_zeroes_at(
    _file: &std::fs::File,
    _offset: u64,
    _length: usize,
) -> std::io::Result<usize> {
    todo!();
}

pub mod syslog {
    pub struct PlatformSyslog {}

    impl crate::syslog::Syslog for PlatformSyslog {
        fn new(
            _proc_name: String,
            _facility: crate::syslog::Facility,
        ) -> Result<
            (
                Option<Box<dyn crate::syslog::Log + Send>>,
                Option<crate::RawDescriptor>,
            ),
            crate::syslog::Error,
        > {
            todo!();
        }
    }
}

impl PartialEq for crate::SafeDescriptor {
    fn eq(&self, _other: &Self) -> bool {
        todo!();
    }
}

impl crate::shm::PlatformSharedMemory for crate::SharedMemory {
    fn new(_debug_name: &std::ffi::CStr, _size: u64) -> crate::Result<crate::SharedMemory> {
        todo!();
    }
    fn from_safe_descriptor(
        _descriptor: crate::SafeDescriptor,
        _size: u64,
    ) -> crate::Result<crate::SharedMemory> {
        todo!();
    }
}

pub(crate) use libc::off_t;
pub(crate) use libc::pread;
pub(crate) use libc::preadv;
pub(crate) use libc::pwrite;
pub(crate) use libc::pwritev;

/// Spawns a pipe pair where the first pipe is the read end and the second pipe is the write end.
///
/// The `O_CLOEXEC` flag will be applied after pipe creation.
pub fn pipe() -> crate::errno::Result<(File, File)> {
    let mut pipe_fds = [-1; 2];
    // SAFETY:
    // Safe because pipe will only write 2 element array of i32 to the given pointer, and we check
    // for error.
    let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    if ret == -1 {
        return crate::errno::errno_result();
    }

    // SAFETY:
    // Safe because both fds must be valid for pipe to have returned sucessfully and we have
    // exclusive ownership of them.
    let pipes = unsafe {
        (
            File::from_raw_descriptor(pipe_fds[0]),
            File::from_raw_descriptor(pipe_fds[1]),
        )
    };

    set_descriptor_cloexec(&pipes.0)?;
    set_descriptor_cloexec(&pipes.1)?;

    Ok(pipes)
}

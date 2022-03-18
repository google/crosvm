// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use crate::unix::{
    add_fd_flags, block_signal, chown, clear_fd_flags, clear_signal, clone_descriptor,
    drop_capabilities, enable_core_scheduling, errno_result, flock, get_blocked_signals,
    get_cpu_affinity, get_filesystem_type, get_max_open_files, getegid, geteuid, getpid, gettid,
    iov_max, kernel_has_memfd, kill_process_group,
    net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener},
    new_pipe_full, open_file, pagesize, pipe, read_raw_stdin, reap_child,
    register_rt_signal_handler, round_up_to_page_size, safe_descriptor_from_path, set_cpu_affinity,
    set_rt_prio_limit, set_rt_round_robin, signal, syslog, unblock_signal, validate_raw_fd,
    with_as_descriptor, with_raw_descriptor, AcpiNotifyEvent, AsRawDescriptor, Clock, Descriptor,
    EpollContext, EpollEvents, Error, EventFd, ExternalMapping, ExternalMappingError,
    ExternalMappingResult, FakeClock, Fd, FileFlags, FlockOperation, FromRawDescriptor,
    IntoRawDescriptor, Killable, LayoutAllocation, MappedRegion, MemfdSeals, MemoryMappingArena,
    MmapError, NetlinkGenericSocket, PollContext, PollToken, Protection, PunchHole, RawDescriptor,
    Result, SafeDescriptor, ScmSocket, SignalFd, Terminal, TimerFd, UnlinkUnixListener,
    UnsyncMarker, WatchingEvents, WriteZeroes, INVALID_DESCRIPTOR, SIGRTMIN,
};
pub mod common;
mod event;
mod ioctl;
mod mmap;
mod shm;
mod timer;
mod tube;
pub mod unix;
mod wait_context;

pub use crate::unix::{
    ioctl::*, FileAllocate, FileGetLen, FileReadWriteAtVolatile, FileReadWriteVolatile, FileSetLen,
    FileSync, WriteZeroesAt,
};
pub use event::{Event, EventReadResult, ScopedEvent};
pub use ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};
pub use mmap::{
    MemoryMapping, MemoryMappingBuilder, MemoryMappingBuilderUnix, Unix as MemoryMappingUnix,
};
pub use shm::{SharedMemory, Unix as SharedMemoryUnix};
pub use timer::{FakeTimer, Timer};
pub use tube::{Error as TubeError, Result as TubeResult, Tube};
pub use wait_context::{EventToken, EventType, TriggeredEvent, WaitContext};

/// Wraps an AsRawDescriptor in the simple Descriptor struct, which
/// has AsRawFd methods for interfacing with sys_util
pub fn wrap_descriptor(descriptor: &dyn AsRawDescriptor) -> Descriptor {
    Descriptor(descriptor.as_raw_descriptor())
}

/// Verifies that |raw_descriptor| is actually owned by this process and duplicates it
/// to ensure that we have a unique handle to it.
pub fn validate_raw_descriptor(raw_descriptor: RawDescriptor) -> Result<RawDescriptor> {
    validate_raw_fd(raw_descriptor)
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
}

impl<T> AsRawDescriptors for T
where
    T: AsRawDescriptor,
{
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.as_raw_descriptor()]
    }
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use sys_util::chown;
pub use sys_util::drop_capabilities;
pub use sys_util::handle_eintr_errno;
pub use sys_util::iov_max;
pub use sys_util::kernel_has_memfd;
pub use sys_util::pipe;
pub use sys_util::read_raw_stdin;
pub use sys_util::syscall;
pub use sys_util::syslog;
pub use sys_util::EventFd;
pub use sys_util::Fd;
pub use sys_util::SignalFd;
pub use sys_util::Terminal;
pub use sys_util::TimerFd;
pub use sys_util::UnsyncMarker;
pub use sys_util::{add_fd_flags, clear_fd_flags};
pub use sys_util::{
    block_signal, clear_signal, get_blocked_signals, register_rt_signal_handler, signal,
    unblock_signal, Killable, SIGRTMIN,
};
pub use sys_util::{
    clone_descriptor, get_max_open_files, safe_descriptor_from_path, validate_raw_fd,
    with_as_descriptor, with_raw_descriptor, AsRawDescriptor, Descriptor, FromRawDescriptor,
    IntoRawDescriptor, RawDescriptor, SafeDescriptor, INVALID_DESCRIPTOR,
};
pub use sys_util::{debug, error, info, warn};
pub use sys_util::{
    enable_core_scheduling, get_cpu_affinity, set_cpu_affinity, set_rt_prio_limit,
    set_rt_round_robin,
};
pub use sys_util::{errno_result, Error, Result};
pub use sys_util::{flock, FlockOperation};
pub use sys_util::{get_filesystem_type, open_file, FileFlags, PunchHole, WriteZeroes};
pub use sys_util::{getegid, geteuid};
pub use sys_util::{getpid, gettid, kill_process_group, reap_child};
pub use sys_util::{ioctl_io_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};
pub use sys_util::{
    net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener},
    ScmSocket, UnlinkUnixListener,
};
pub use sys_util::{pagesize, round_up_to_page_size};
pub use sys_util::{Clock, FakeClock};
pub use sys_util::{EpollContext, EpollEvents};
pub use sys_util::{ExternalMapping, ExternalMappingError, ExternalMappingResult};
pub use sys_util::{
    LayoutAllocation, MappedRegion, MemfdSeals, MemoryMappingArena, MmapError, Protection,
};
pub use sys_util::{PollToken, WatchingEvents};

mod async_types;
mod event;
mod ioctl;
mod mmap;
mod shm;
mod timer;
mod tube;
mod wait_context;

pub use async_types::*;
pub use event::{Event, EventReadResult, ScopedEvent};
pub use ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};
pub use mmap::Unix as MemoryMappingUnix;
pub use mmap::{MemoryMapping, MemoryMappingBuilder, MemoryMappingBuilderUnix};
pub use shm::{SharedMemory, Unix as SharedMemoryUnix};
pub use sys_util::ioctl::*;
pub use sys_util::{
    volatile_at_impl, volatile_impl, FileAllocate, FileGetLen, FileReadWriteAtVolatile,
    FileReadWriteVolatile, FileSetLen, FileSync, WriteZeroesAt,
};
pub use timer::{FakeTimer, Timer};
pub use tube::{AsyncTube, Error as TubeError, Result as TubeResult, Tube};
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

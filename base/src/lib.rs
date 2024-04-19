// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Safe, cross-platform-compatible wrappers for system interfaces.

mod alloc;
mod clock;
pub mod custom_serde;
pub mod descriptor;
pub mod descriptor_reflection;
mod errno;
mod event;
mod file_traits;
mod iobuf;
mod mmap;
mod notifiers;
mod periodic_logger;
mod shm;
pub mod syslog;
pub mod test_utils;
mod timer;
mod tube;
mod volatile_memory;
mod wait_context;
mod worker_thread;
mod write_zeroes;

pub mod sys;
pub use alloc::LayoutAllocation;

pub use clock::Clock;
pub use clock::FakeClock;
pub use errno::errno_result;
pub use errno::Error;
pub use errno::Result;
pub use event::Event;
pub use event::EventWaitResult;
pub use file_traits::FileAllocate;
pub use file_traits::FileGetLen;
pub use file_traits::FileReadWriteAtVolatile;
pub use file_traits::FileReadWriteVolatile;
pub use file_traits::FileSetLen;
pub use file_traits::FileSync;
pub use iobuf::IoBufMut;
pub use mmap::Error as MmapError;
pub use mmap::ExternalMapping;
pub use mmap::MappedRegion;
pub use mmap::MemoryMapping;
pub use mmap::MemoryMappingBuilder;
pub use mmap::Result as MmapResult;
pub use notifiers::CloseNotifier;
pub use notifiers::ReadNotifier;
pub use platform::ioctl::ioctl;
pub use platform::ioctl::ioctl_with_mut_ptr;
pub use platform::ioctl::ioctl_with_mut_ref;
pub use platform::ioctl::ioctl_with_ptr;
pub use platform::ioctl::ioctl_with_ref;
pub use platform::ioctl::ioctl_with_val;
pub use platform::ioctl::IoctlNr;
pub use shm::SharedMemory;
use sys::platform;
pub use timer::FakeTimer;
pub use timer::Timer;
pub use timer::TimerTrait;
pub use tube::Error as TubeError;
#[cfg(any(windows, feature = "proto_tube"))]
pub use tube::ProtoTube;
pub use tube::RecvTube;
pub use tube::Result as TubeResult;
pub use tube::SendTube;
pub use tube::Tube;
pub use volatile_memory::VolatileMemory;
pub use volatile_memory::VolatileMemoryError;
pub use volatile_memory::VolatileMemoryResult;
pub use volatile_memory::VolatileSlice;
pub use wait_context::EventToken;
pub use wait_context::EventType;
pub use wait_context::TriggeredEvent;
pub use wait_context::WaitContext;
pub use worker_thread::WorkerThread;
pub use write_zeroes::PunchHole;
pub use write_zeroes::PunchHoleMut;
pub use write_zeroes::WriteZeroesAt;

// TODO(b/233233301): reorganize platform specific exports under platform
// namespaces instead of exposing them directly in base::.
cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub use sys::linux;

        // descriptor/fd related exports.
        pub use linux::{
            clone_descriptor, safe_descriptor_from_path,
            validate_raw_descriptor, clear_descriptor_cloexec,
        };

        // Event/signal related exports.
        pub use linux::{
            block_signal, clear_signal, get_blocked_signals, new_pipe_full,
            register_rt_signal_handler, signal, unblock_signal, Killable, SIGRTMIN,
            AcpiNotifyEvent, NetlinkGenericSocket, SignalFd, Terminal,
        };

        pub use linux::{
            drop_capabilities, pipe, read_raw_stdin
        };
        pub use linux::{enable_core_scheduling, set_rt_prio_limit, set_rt_round_robin};
        pub use linux::{flock, FlockOperation};
        pub use linux::{getegid, geteuid};
        pub use linux::{gettid, kill_process_group, reap_child};
        pub use linux::logical_core_capacity;
        pub use linux::logical_core_cluster_id;
        pub use linux::logical_core_frequencies_khz;
        pub use linux::sched_attr;
        pub use linux::sched_setattr;
        pub use linux::UnlinkUnixListener;
        pub use linux::EventExt;
        pub use linux::Gid;
    }
}

cfg_if::cfg_if! {
     if #[cfg(windows)] {
        pub use sys::windows;

        pub use windows::{EventTrigger, EventExt, WaitContextExt};
        pub use windows::IoBuf;
        pub use windows::MemoryMappingBuilderWindows;
        pub use windows::set_thread_priority;
        pub use windows::{give_foregrounding_permission, Console};
        pub use windows::{named_pipes, named_pipes::PipeConnection};
        pub use windows::{SafeMultimediaHandle, MAXIMUM_WAIT_OBJECTS};
        pub use windows::set_sparse_file;
        pub use windows::ioctl::ioctl_with_ptr_sized;
        pub use windows::create_overlapped;
        pub use windows::device_io_control;
        pub use windows::number_of_logical_cores;
        pub use windows::pagesize;
        pub use windows::read_overlapped_blocking;

        pub use tube::{
            deserialize_and_recv, serialize_and_send, set_alias_pid, set_duplicate_handle_tube,
            DuplicateHandleRequest, DuplicateHandleResponse, DuplicateHandleTube
        };
        pub use tube::PipeTube;
        pub use tube::FlushOnDropTube;
        pub use windows::{set_audio_thread_priority, thread};
        pub use windows::Pid;
        pub use windows::Terminal;
    }
}

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub use sys::unix;

        pub use unix::IoBuf;
        pub use unix::net::UnixSeqpacket;
        pub use unix::net::UnixSeqpacketListener;
        pub use unix::net::UnlinkUnixSeqpacketListener;
        pub use unix::ScmSocket;
        pub use unix::SCM_SOCKET_MAX_FD_COUNT;
        pub use unix::add_fd_flags;
        pub use unix::clear_fd_flags;
        pub use unix::number_of_logical_cores;
        pub use unix::pagesize;
        pub use unix::Pid;
    }
}

pub use descriptor_reflection::deserialize_with_descriptors;
pub use descriptor_reflection::with_as_descriptor;
pub use descriptor_reflection::with_raw_descriptor;
pub use descriptor_reflection::FileSerdeWrapper;
pub use descriptor_reflection::SerializeDescriptors;
pub use log::debug;
pub use log::error;
pub use log::info;
pub use log::trace;
pub use log::warn;
pub use mmap::Protection;
pub use platform::get_cpu_affinity;
pub use platform::get_filesystem_type;
pub use platform::getpid;
pub use platform::open_file_or_duplicate;
pub use platform::platform_timer_resolution::enable_high_res_timers;
pub use platform::set_cpu_affinity;
pub use platform::BlockingMode;
pub use platform::EventContext;
pub use platform::FramingMode;
pub use platform::MemoryMappingArena;
pub use platform::RawDescriptor;
pub use platform::StreamChannel;
pub use platform::INVALID_DESCRIPTOR;
use uuid::Uuid;

pub use crate::descriptor::AsRawDescriptor;
pub use crate::descriptor::AsRawDescriptors;
pub use crate::descriptor::Descriptor;
pub use crate::descriptor::FromRawDescriptor;
pub use crate::descriptor::IntoRawDescriptor;
pub use crate::descriptor::SafeDescriptor;

/// An empty trait that helps reset timer resolution to its previous state.
// TODO(b:232103460): Maybe this needs to be thought through.
pub trait EnabledHighResTimer {}

/// Creates a UUID.
pub fn generate_uuid() -> String {
    let mut buf = Uuid::encode_buffer();
    Uuid::new_v4()
        .as_hyphenated()
        .encode_lower(&mut buf)
        .to_owned()
}

use serde::Deserialize;
use serde::Serialize;
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum VmEventType {
    Exit,
    Reset,
    Crash,
    Panic(u8),
    WatchdogReset,
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}

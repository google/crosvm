// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Safe, cross-platform-compatible wrappers for system interfaces.

mod alloc;
mod clock;
pub mod descriptor;
pub mod descriptor_reflection;
mod errno;
mod event;
pub mod external_mapping;
mod mmap;
mod notifiers;
mod shm;
pub mod syslog;
mod timer;
mod tube;
mod wait_context;
mod write_zeroes;

pub mod sys;
pub use sys::platform;

pub use alloc::LayoutAllocation;
pub use clock::{Clock, FakeClock};
pub use errno::{errno_result, Error, Result};
pub use event::{Event, EventReadResult};
pub use external_mapping::{
    Error as ExternalMappingError, ExternalMapping, Result as ExternalMappingResult,
};
pub use mmap::{MemoryMapping, MemoryMappingBuilder};
pub use notifiers::{CloseNotifier, ReadNotifier};
pub use platform::ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
    IoctlNr,
};
pub use shm::SharedMemory;
pub use timer::{FakeTimer, Timer};
pub use tube::{Error as TubeError, RecvTube, Result as TubeResult, SendTube, Tube};
pub use wait_context::{EventToken, EventType, TriggeredEvent, WaitContext};
pub use write_zeroes::{PunchHole, WriteZeroesAt};

// TODO(b/233233301): reorganize platform specific exports under platform
// namespaces instead of exposing them directly in base::.
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub use sys::unix;

        pub use unix::net;

        // File related exports.
        pub use platform::{FileFlags, get_max_open_files};

        // memory/mmap related exports.
        pub use platform::{
            MemfdSeals, MemoryMappingBuilderUnix, Unix as MemoryMappingUnix,
            SharedMemoryUnix,
        };

        // descriptor/fd related exports.
        pub use platform::{
            add_fd_flags, clear_fd_flags, clone_descriptor, safe_descriptor_from_path,
            validate_raw_descriptor, clear_descriptor_cloexec,
        };

        // Event/signal related exports.
        pub use platform::{
            block_signal, clear_signal, get_blocked_signals, new_pipe_full,
            register_rt_signal_handler, signal, unblock_signal, Killable, SIGRTMIN,
            WatchingEvents, AcpiNotifyEvent, NetlinkGenericSocket, SignalFd, Terminal, EventFd,
        };

        pub use platform::{
            chown, drop_capabilities, iov_max, kernel_has_memfd, pipe, read_raw_stdin
        };
        pub use platform::{enable_core_scheduling, set_rt_prio_limit, set_rt_round_robin};
        pub use platform::{flock, FlockOperation};
        pub use platform::{getegid, geteuid};
        pub use platform::{gettid, kill_process_group, reap_child};
        pub use platform::{
            net::{UnixSeqpacket, UnixSeqpacketListener, UnlinkUnixSeqpacketListener},
            ScmSocket, UnlinkUnixListener, SCM_SOCKET_MAX_FD_COUNT,
        };
    } else if #[cfg(windows)] {
        pub use platform::{EventTrigger, EventExt, WaitContextExt};
        pub use platform::MemoryMappingBuilderWindows;
        pub use platform::set_thread_priority;
        pub use platform::{give_foregrounding_permission, Console};
        pub use platform::{named_pipes, named_pipes::PipeConnection};
        pub use platform::{SafeMultimediaHandle, MAXIMUM_WAIT_OBJECTS};
        pub use crate::platform::win::{
            measure_timer_resolution, nt_query_timer_resolution, nt_set_timer_resolution,
            set_sparse_file, set_time_period,
        };
        pub use platform::ioctl::ioctl_with_ptr_sized;

        pub use tube::{
            deserialize_and_recv, serialize_and_send, set_alias_pid, set_duplicate_handle_tube,
            DuplicateHandleRequest, DuplicateHandleResponse, DuplicateHandleTube,
        };
        pub use platform::{set_audio_thread_priorities, thread};
        pub use platform::{BlockingMode, FramingMode, StreamChannel};
        pub use platform::gmtime_secure;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub use platform::{
    deserialize_with_descriptors, EventContext, FileAllocate, FileGetLen, FileSerdeWrapper,
    SerializeDescriptors, UnsyncMarker,
};

use uuid::Uuid;

pub use platform::Protection;
pub(crate) use platform::{file_punch_hole, file_write_zeroes_at};
pub use platform::{get_cpu_affinity, set_cpu_affinity};
pub use platform::{with_as_descriptor, with_raw_descriptor, RawDescriptor, INVALID_DESCRIPTOR};

pub use crate::descriptor::{
    AsRawDescriptor, AsRawDescriptors, Descriptor, FromRawDescriptor, IntoRawDescriptor,
    SafeDescriptor,
};

pub use platform::getpid;
pub use platform::platform_timer_resolution::enable_high_res_timers;
pub use platform::{get_filesystem_type, open_file};
pub use platform::{number_of_logical_cores, pagesize, round_up_to_page_size};
pub use platform::{FileReadWriteAtVolatile, FileReadWriteVolatile, FileSetLen, FileSync};
pub use platform::{MappedRegion, MemoryMappingArena, MmapError};

pub use log::{debug, error, info, trace, warn};

/// An empty trait that helps reset timer resolution to its previous state.
// TODO(b:232103460): Maybe this needs to be thought through.
pub trait EnabledHighResTimer {}

/// Creates a UUID.
pub fn generate_uuid() -> String {
    let mut buf = Uuid::encode_buffer();
    Uuid::new_v4()
        .to_hyphenated()
        .encode_lower(&mut buf)
        .to_owned()
}

use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq)]
pub enum VmEventType {
    Exit,
    Reset,
    Crash,
    Panic(u8),
}

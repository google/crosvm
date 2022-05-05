// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod alloc;
mod clock;
pub mod descriptor;
pub mod descriptor_reflection;
mod errno;
mod event;
pub mod external_mapping;
mod mmap;
mod notifiers;
pub mod scoped_event_macro;
mod shm;
pub mod syslog;
mod timer;
mod tube;

pub mod sys;
pub use sys::platform;

pub use alloc::LayoutAllocation;
pub use clock::{Clock, FakeClock};
pub use errno::{errno_result, Error, Result};
pub use event::{Event, EventReadResult, ScopedEvent};
pub use external_mapping::{Error as ExternalMappingError, Result as ExternalMappingResult, *};
pub use mmap::{MemoryMapping, MemoryMappingBuilder};
pub use notifiers::*;
pub use platform::ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
    *,
};
pub use scoped_event_macro::*;
pub use shm::SharedMemory;
pub use timer::{FakeTimer, Timer};
pub use tube::{Error as TubeError, RecvTube, Result as TubeResult, SendTube, Tube};

cfg_if::cfg_if! {
     if #[cfg(unix)] {
        mod wait_context;

        pub use sys::unix;

        pub use unix::net::*;

        pub use platform::{MemoryMappingBuilderUnix, Unix as MemoryMappingUnix};
        pub use wait_context::{EventToken, EventType, TriggeredEvent, WaitContext};
     } else if #[cfg(windows)] {
        pub use platform::MemoryMappingBuilderWindows;
        pub use platform::EventExt;
        pub use tube::{deserialize_and_recv, serialize_and_send, set_duplicate_handle_tube, set_alias_pid, DuplicateHandleTube};
     } else {
        compile_error!("Unsupported platform");
     }
}

pub use crate::descriptor::{
    AsRawDescriptor, AsRawDescriptors, Descriptor, FromRawDescriptor, IntoRawDescriptor,
    SafeDescriptor,
};
pub use log::*;
pub use platform::*;

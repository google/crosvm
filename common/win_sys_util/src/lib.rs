// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

#![cfg(windows)]

#[macro_use]
pub mod win;

#[path = "win/ioctl.rs"]
#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod clock;
#[path = "win/console.rs"]
mod console;
mod descriptor;
mod descriptor_reflection;
#[path = "win/event.rs"]
mod event;
mod events;
pub mod file_traits;
#[path = "win/get_filesystem_type.rs"]
mod get_filesystem_type;
mod gmtime;
mod mmap;
#[path = "win/named_pipes.rs"]
pub mod named_pipes;
mod notifiers;
mod poll;
#[path = "win/priority.rs"]
mod priority;
mod scoped_event;
// Add conditional compile?
#[path = "win/sched.rs"]
mod sched;
mod shm;
mod stream_channel;
mod timer;

pub mod thread;

mod write_zeroes;

pub use crate::clock::{Clock, FakeClock};
pub use crate::console::*;
pub use crate::descriptor::*;
pub use crate::event::*;
pub use crate::events::*;
pub use crate::get_filesystem_type::*;
pub use crate::gmtime::*;
pub use crate::ioctl::*;
pub use crate::mmap::*;
pub use crate::notifiers::*;
pub use crate::poll::*;
pub use crate::priority::*;
pub use crate::sched::*;
pub use crate::scoped_event::*;
pub use crate::shm::*;
pub use crate::stream_channel::*;
pub use crate::timer::*;
pub use crate::win::*;
pub use descriptor_reflection::{
    deserialize_with_descriptors, with_as_descriptor, with_raw_descriptor, FileSerdeWrapper,
    SerializeDescriptors,
};
pub use poll_token_derive::*;
pub use sys_util_core::{Error, Result, *};

pub use crate::file_traits::{
    AsRawDescriptors, FileAllocate, FileGetLen, FileReadWriteAtVolatile, FileReadWriteVolatile,
    FileSetLen, FileSync,
};
pub use crate::mmap::Error as MmapError;
pub use crate::write_zeroes::{PunchHole, WriteZeroes, WriteZeroesAt};

use std::cell::Cell;

// Define libc::* types
#[allow(non_camel_case_types)]
pub type pid_t = i32;
#[allow(non_camel_case_types)]
pub type uid_t = u32;
#[allow(non_camel_case_types)]
pub type gid_t = u32;
#[allow(non_camel_case_types)]
pub type mode_t = u32;

/// Re-export libc types that are part of the API.
pub type Pid = pid_t;
pub type Uid = uid_t;
pub type Gid = gid_t;
pub type Mode = mode_t;

/// Used to mark types as !Sync.
pub type UnsyncMarker = std::marker::PhantomData<Cell<usize>>;

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}

#[macro_export]
macro_rules! CHRONO_TIMESTAMP_FIXED_FMT {
    () => {
        "%F %T%.9f"
    };
}

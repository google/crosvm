// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

#![cfg(windows)]

#[macro_use]
pub mod win;

#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod console;
mod descriptor;
mod event;
mod events;
pub mod file_traits;
mod get_filesystem_type;
mod mmap;
mod mmap_platform;
pub mod named_pipes;
pub mod platform_timer_resolution;
mod priority;
// Add conditional compile?
mod punch_hole;
mod read_write_wrappers;
mod sched;
mod shm;
mod shm_platform;
mod stream_channel;
mod terminal;
mod timer;
mod wait;

pub mod thread;

mod write_zeroes;

pub use console::*;
pub use descriptor::*;
pub use event::*;
pub use events::*;
pub use get_filesystem_type::*;
pub use ioctl::*;
pub use mmap::Error as MmapError;
pub use mmap::*;
pub(crate) use mmap_platform::PROT_READ;
pub(crate) use mmap_platform::PROT_WRITE;
pub use priority::*;
pub(crate) use punch_hole::file_punch_hole;
pub use read_write_wrappers::*;
pub use sched::*;
pub use shm::*;
pub use shm_platform::*;
pub use stream_channel::*;
pub use terminal::*;
pub use timer::*;
pub use win::*;
pub(crate) use write_zeroes::file_write_zeroes_at;

pub use crate::descriptor_reflection::deserialize_with_descriptors;
pub use crate::descriptor_reflection::with_as_descriptor;
pub use crate::descriptor_reflection::with_raw_descriptor;
pub use crate::descriptor_reflection::FileSerdeWrapper;
pub use crate::descriptor_reflection::SerializeDescriptors;
pub use crate::errno::Error;
pub use crate::errno::Result;
pub use crate::errno::*;

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

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}

/// Returns the number of online logical cores on the system.
pub fn number_of_logical_cores() -> Result<usize> {
    Ok(win_util::number_of_processors())
}

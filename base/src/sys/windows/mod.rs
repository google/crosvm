// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

#![cfg(windows)]

#[macro_use]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod console;
mod descriptor;
mod event;
mod events;
pub mod file_traits;
mod file_util;
mod foreground_window;
mod get_filesystem_type;
mod mmap;
mod mmap_platform;
mod multi_process_mutex;
pub mod named_pipes;
pub mod platform_timer_resolution;
mod platform_timer_utils;
mod priority;
// Add conditional compile?
mod punch_hole;
mod read_write_wrappers;
mod sched;
mod shm;
mod stream_channel;
mod system_info;
mod terminal;
mod timer;
pub mod tube;
mod wait;

pub mod thread;

mod write_zeroes;

pub use console::*;
pub use descriptor::*;
pub use event::*;
pub use events::*;
pub use file_util::get_allocated_ranges;
pub use file_util::open_file_or_duplicate;
pub use file_util::set_sparse_file;
pub use foreground_window::give_foregrounding_permission;
pub use get_filesystem_type::*;
pub use ioctl::*;
pub use mmap::Error as MmapError;
pub use mmap::*;
pub(crate) use mmap_platform::PROT_READ;
pub(crate) use mmap_platform::PROT_WRITE;
pub(crate) use multi_process_mutex::MultiProcessMutex;
pub use priority::*;
pub(crate) use punch_hole::file_punch_hole;
pub use read_write_wrappers::*;
pub use sched::*;
pub use stream_channel::*;
pub use system_info::allocation_granularity;
pub use system_info::getpid;
pub use system_info::number_of_logical_cores;
pub use system_info::pagesize;
pub use system_info::round_up_to_page_size;
pub use terminal::*;
pub use timer::*;
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

/// Returns a list of supported frequencies in kHz for a given logical core.
/// This is currently not supported on Windows.
pub fn logical_core_frequencies_khz(_cpu_id: usize) -> Result<Vec<u32>> {
    Err(Error::new(libc::ENOTSUP))
}

/// Stub impl for sched_attr.
/// This is currently not supported on Windows.
#[repr(C)]
pub struct sched_attr {
    pub sched_flags: u64,
    pub sched_util_min: u32,
}

impl sched_attr {
    pub fn default() -> Self {
        Self {
            sched_flags: 0,
            sched_util_min: 0,
        }
    }
}

/// Sets scheduler related attributes for tasks.
/// This is currently not supported on Windows.
pub fn sched_setattr(_pid: Pid, _attr: &mut sched_attr, _flags: u32) -> Result<()> {
    Err(Error::new(libc::ENOTSUP))
}

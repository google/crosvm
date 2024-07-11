// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod descriptor;
mod memory_mapping;
mod shm;
pub mod sys;

pub use descriptor::AsRawDescriptor;
pub use descriptor::FromRawDescriptor;
pub use descriptor::IntoRawDescriptor;
pub use descriptor::SafeDescriptor;
pub use memory_mapping::MemoryMapping;
pub use shm::SharedMemory;
pub use sys::platform::descriptor::RawDescriptor;
pub use sys::platform::shm::round_up_to_page_size;
pub use sys::platform::wait_context::WaitContext;

use crate::rutabaga_utils::RutabagaMapping;

pub struct WaitEvent {
    pub connection_id: u64,
    pub hung_up: bool,
    pub readable: bool,
}

#[allow(dead_code)]
const WAIT_CONTEXT_MAX: usize = 16;

#[allow(dead_code)]
pub trait WaitTrait {}

/// # Safety
///
/// Caller must ensure that MappedRegion's lifetime contains the lifetime of
/// pointer returned.
pub unsafe trait MappedRegion: Send + Sync {
    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8;

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize;

    /// Returns rutabaga mapping representation of the region
    fn as_rutabaga_mapping(&self) -> RutabagaMapping;
}

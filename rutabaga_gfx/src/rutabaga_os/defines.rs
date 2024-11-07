// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use crate::rutabaga_utils::RutabagaMapping;

pub enum TubeType {
    Stream,
    Packet,
}

pub enum WaitTimeout {
    Finite(Duration),
    NoTimeout,
}

pub struct WaitEvent {
    pub connection_id: u64,
    pub hung_up: bool,
    pub readable: bool,
}

#[allow(dead_code)]
pub const WAIT_CONTEXT_MAX: usize = 16;

pub enum DescriptorType {
    Unknown,
    Memory(u32),
    WritePipe,
}

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

// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::ffi::c_void;

use crate::MesaError;
use crate::MesaResult;
use crate::OwnedDescriptor;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    pub addr: *mut c_void,
    pub size: usize,
}

// SAFETY:
// MemoryMapping user must ensure it is used by one thread at a time.
unsafe impl Sync for MemoryMapping {}

// SAFETY:
// MemoryMapping user must ensure it is used by one thread at a time.
unsafe impl Send for MemoryMapping {}

impl MemoryMapping {
    pub fn from_safe_descriptor(
        _descriptor: OwnedDescriptor,
        _size: usize,
        _map_info: u32,
    ) -> MesaResult<MemoryMapping> {
        Err(MesaError::Unsupported)
    }

    pub fn from_offset(
        _descriptor: &OwnedDescriptor,
        _offset: usize,
        _size: usize,
    ) -> MesaResult<MemoryMapping> {
        Err(MesaError::Unsupported)
    }
}

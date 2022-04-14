// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use win_util::create_file_mapping;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use super::super::{shm::SharedMemory, MemoryMapping, MmapError, Result};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};

impl SharedMemory {
    /// Creates a new shared memory file mapping with zero size.
    pub fn new(name: Option<&CStr>, size: u64) -> Result<Self> {
        // Safe because we do not provide a handle.
        let mapping_handle = unsafe {
            create_file_mapping(
                None,
                size,
                PAGE_EXECUTE_READWRITE,
                name.map(|s| s.to_str().unwrap()),
            )
        }
        .map_err(super::super::Error::from)?;

        // Safe because we have exclusive ownership of mapping_handle & it is valid.
        Self::from_safe_descriptor(
            unsafe { SafeDescriptor::from_raw_descriptor(mapping_handle) },
            size,
        )
    }

    pub fn from_safe_descriptor(mapping_handle: SafeDescriptor, size: u64) -> Result<Self> {
        let mapping = match MemoryMapping::from_raw_descriptor(
            mapping_handle.as_raw_descriptor(),
            size as usize,
        ) {
            Ok(mapping) => mapping,
            Err(e) => {
                return match e {
                    MmapError::SystemCallFailed(e) => Err(e),
                    // TODO(b/150414994): This error lacks meaning. Consider adding custom errors to
                    // shm
                    _ => Err(super::super::Error::new(0)),
                };
            }
        };

        Ok(SharedMemory {
            descriptor: mapping_handle,
            size,
            mapping,
            cursor: 0,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use winapi::shared::winerror::ERROR_NOT_ENOUGH_MEMORY;

    #[test]
    fn new_too_huge() {
        let result = SharedMemory::anon(0x8000_0000_0000_0000);
        assert_eq!(
            result.err().unwrap().errno(),
            ERROR_NOT_ENOUGH_MEMORY as i32
        );
    }
}

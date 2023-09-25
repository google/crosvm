// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;

use win_util::create_file_mapping;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::shm::PlatformSharedMemory;
use crate::Result;
use crate::SharedMemory;

impl PlatformSharedMemory for SharedMemory {
    fn new(_debug_name: &CStr, size: u64) -> Result<SharedMemory> {
        // Safe because we do not provide a handle.
        let mapping_handle =
            unsafe { create_file_mapping(None, size, PAGE_EXECUTE_READWRITE, None) }
                .map_err(super::Error::from)?;

        // Safe because we have exclusive ownership of mapping_handle & it is valid.
        Self::from_safe_descriptor(
            unsafe { SafeDescriptor::from_raw_descriptor(mapping_handle) },
            size,
        )
    }

    fn from_safe_descriptor(mapping_handle: SafeDescriptor, size: u64) -> Result<SharedMemory> {
        Ok(SharedMemory {
            descriptor: mapping_handle,
            size,
        })
    }
}

#[cfg(test)]
mod test {
    use winapi::shared::winerror::ERROR_NOT_ENOUGH_MEMORY;

    use super::*;

    #[cfg_attr(all(target_os = "windows", target_env = "gnu"), ignore)]
    #[test]
    fn new_too_huge() {
        let result = SharedMemory::new("test", 0x8000_0000_0000_0000);
        assert_eq!(
            result.err().unwrap().errno(),
            ERROR_NOT_ENOUGH_MEMORY as i32
        );
    }
}

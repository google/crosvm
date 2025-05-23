// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use mesa3d_util::AsRawDescriptor;
use mesa3d_util::MesaError;
use mesa3d_util::MesaHandle;
use mesa3d_util::MESA_HANDLE_TYPE_MEM_OPAQUE_WIN32;
use vulkano::device::Device;
use vulkano::device::DeviceExtensions;
use vulkano::memory::DeviceMemory;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryImportInfo;

use crate::rutabaga_gralloc::vulkano_gralloc::VulkanoGralloc;
use crate::RutabagaResult;

impl VulkanoGralloc {
    /// Get the extensions that should be enabled.
    pub(crate) fn get_desired_device_extensions() -> DeviceExtensions {
        DeviceExtensions {
            khr_dedicated_allocation: true,
            khr_get_memory_requirements2: true,
            khr_external_memory: true,
            khr_external_memory_win32: true,
            ..DeviceExtensions::empty()
        }
    }

    /// Import memory from a handle.
    ///
    /// # Safety
    /// Safe if the memory handle given is an opaque Win32 handle, and the allocation info matches
    /// the information at the time the memory was created.
    pub(crate) unsafe fn import_memory(
        device: Arc<Device>,
        allocate_info: MemoryAllocateInfo,
        handle: MesaHandle,
    ) -> RutabagaResult<DeviceMemory> {
        let import_info = MemoryImportInfo::Win32 {
            handle_type: match handle.handle_type {
                MESA_HANDLE_TYPE_MEM_OPAQUE_WIN32 => ExternalMemoryHandleType::OpaqueWin32,
                _ => return Err(MesaError::InvalidMesaHandle.into()),
            },
            handle: handle.os_handle.as_raw_descriptor(),
        };

        Ok(DeviceMemory::import(device, allocate_info, import_info)?)
    }
}

// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use std::fmt;
use std::time::Duration;

use crate::error::MesaError;
use crate::error::MesaResult;
use crate::OwnedDescriptor;

/// Mapped memory caching flags (see virtio_gpu spec)
pub const MESA_MAP_CACHE_MASK: u32 = 0x0f;
pub const MESA_MAP_CACHE_CACHED: u32 = 0x01;
pub const MESA_MAP_CACHE_UNCACHED: u32 = 0x02;
pub const MESA_MAP_CACHE_WC: u32 = 0x03;
/// Access flags (not in virtio_gpu spec)
pub const MESA_MAP_ACCESS_MASK: u32 = 0xf0;
pub const MESA_MAP_ACCESS_READ: u32 = 0x10;
pub const MESA_MAP_ACCESS_WRITE: u32 = 0x20;
pub const MESA_MAP_ACCESS_RW: u32 = 0x30;

/// Mesa handle types (memory and sync in same namespace)
pub const MESA_HANDLE_TYPE_MEM_OPAQUE_FD: u32 = 0x0001;
pub const MESA_HANDLE_TYPE_MEM_DMABUF: u32 = 0x0002;
pub const MESA_HANDLE_TYPE_MEM_OPAQUE_WIN32: u32 = 0x0003;
pub const MESA_HANDLE_TYPE_MEM_SHM: u32 = 0x0004;
pub const MESA_HANDLE_TYPE_MEM_ZIRCON: u32 = 0x0005;

pub const MESA_HANDLE_TYPE_SIGNAL_OPAQUE_FD: u32 = 0x0010;
pub const MESA_HANDLE_TYPE_SIGNAL_SYNC_FD: u32 = 0x0020;
pub const MESA_HANDLE_TYPE_SIGNAL_OPAQUE_WIN32: u32 = 0x0030;
pub const MESA_HANDLE_TYPE_SIGNAL_ZIRCON: u32 = 0x0040;
pub const MESA_HANDLE_TYPE_SIGNAL_EVENT_FD: u32 = 0x0050;

/// Handle to OS-specific memory or synchronization objects.
pub struct MesaHandle {
    pub os_handle: OwnedDescriptor,
    pub handle_type: u32,
}

impl MesaHandle {
    /// Clones an existing Mesahandle, by using OS specific mechanisms.
    pub fn try_clone(&self) -> MesaResult<MesaHandle> {
        let clone = self
            .os_handle
            .try_clone()
            .map_err(|_| MesaError::InvalidMesaHandle)?;
        Ok(MesaHandle {
            os_handle: clone,
            handle_type: self.handle_type,
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MesaMapping {
    pub ptr: u64,
    pub size: u64,
}

impl fmt::Debug for MesaHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle debug").finish()
    }
}

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

    /// Returns mesa mapping representation of the region
    fn as_mesa_mapping(&self) -> MesaMapping;
}

#[macro_export]
macro_rules! log_status {
    ($result:expr) => {
        match $result {
            Ok(_) => (),
            Err(e) => error!("Error recieved: {}", e),
        }
    };
}

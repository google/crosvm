// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::time::Duration;

#[cfg(feature = "gpu")]
use crate::gpu::DisplayModeTrait;

#[cfg(feature = "gpu")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayMode {
    Windowed(u32, u32),
}

#[cfg(feature = "gpu")]
impl DisplayModeTrait for DisplayMode {
    fn get_window_size(&self) -> (u32, u32) {
        match self {
            Self::Windowed(width, height) => (*width, *height),
        }
    }

    fn get_virtual_display_size(&self) -> (u32, u32) {
        self.get_window_size()
    }

    fn get_virtual_display_size_4k_uhd(&self, _is_4k_uhd_enabled: bool) -> (u32, u32) {
        self.get_virtual_display_size()
    }
}

#[cfg(feature = "gpu")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseMode {
    Touchscreen,
}

#[cfg(feature = "gpu")]
impl std::str::FromStr for MouseMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "touchscreen" => Ok(MouseMode::Touchscreen),
            _ => Err(format!("unknown mouse mode: {}", s)),
        }
    }
}

#[cfg(feature = "gpu")]
impl std::fmt::Display for MouseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MouseMode::Touchscreen => write!(f, "touchscreen"),
        }
    }
}

use base::error;
use base::Error as SysError;
use base::MemoryMappingArena;
use base::MmapError;
use base::Protection;
use base::SafeDescriptor;
use base::Tube;
use base::UnixSeqpacket;
use hypervisor::MemCacheType;
use hypervisor::MemSlot;
use hypervisor::Vm;
use libc::EINVAL;
use libc::ERANGE;
use resources::Alloc;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;

use crate::client::HandleRequestResult;
use crate::VmMappedMemoryRegion;
use crate::VmRequest;
use crate::VmResponse;

pub fn handle_request<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
) -> HandleRequestResult {
    handle_request_with_timeout(request, socket_path, None)
}

pub fn handle_request_with_timeout<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
    timeout: Option<Duration>,
) -> HandleRequestResult {
    match UnixSeqpacket::connect(&socket_path) {
        Ok(s) => {
            let socket = Tube::try_from(s).map_err(|_| ())?;
            if timeout.is_some() {
                if let Err(e) = socket.set_recv_timeout(timeout) {
                    error!(
                        "failed to set recv timeout on socket at '{:?}': {}",
                        socket_path, e
                    );
                    return Err(());
                }
            }
            if let Err(e) = socket.send(request) {
                error!(
                    "failed to send request to socket at '{:?}': {}",
                    socket_path, e
                );
                return Err(());
            }
            match socket.recv() {
                Ok(response) => Ok(response),
                Err(e) => {
                    error!(
                        "failed to recv response from socket at '{:?}': {}",
                        socket_path, e
                    );
                    Err(())
                }
            }
        }
        Err(e) => {
            error!("failed to connect to socket at '{:?}': {}", socket_path, e);
            Err(())
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMemoryMappingRequest {
    MsyncArena {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMemoryMappingResponse {
    Ok,
    Err(SysError),
}

impl VmMemoryMappingRequest {
    pub fn execute(&self, vm: &mut impl Vm) -> VmMemoryMappingResponse {
        use self::VmMemoryMappingRequest::*;
        match *self {
            MsyncArena { slot, offset, size } => match vm.msync_memory_region(slot, offset, size) {
                Ok(()) => VmMemoryMappingResponse::Ok,
                Err(e) => VmMemoryMappingResponse::Err(e),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FsMappingRequest {
    AllocateSharedMemoryRegion(Alloc),
    CreateMemoryMapping {
        slot: u32,
        fd: SafeDescriptor,
        size: usize,
        file_offset: u64,
        prot: Protection,
        mem_offset: usize,
    },
    RemoveMemoryMapping {
        slot: u32,
        offset: usize,
        size: usize,
    },
}

pub fn prepare_shared_memory_region(
    vm: &mut dyn Vm,
    allocator: &mut SystemAllocator,
    alloc: Alloc,
    cache: MemCacheType,
) -> Result<VmMappedMemoryRegion, SysError> {
    if !matches!(alloc, Alloc::PciBar { .. }) {
        return Err(SysError::new(EINVAL));
    }
    match allocator.mmio_allocator_any().get(&alloc) {
        Some((range, _)) => {
            let size: usize = match range.len().and_then(|x| x.try_into().ok()) {
                Some(v) => v,
                None => return Err(SysError::new(ERANGE)),
            };
            let arena = match MemoryMappingArena::new(size) {
                Ok(a) => a,
                Err(MmapError::SystemCallFailed(e)) => return Err(e),
                _ => return Err(SysError::new(EINVAL)),
            };

            match vm.add_memory_region(
                GuestAddress(range.start),
                Box::new(arena),
                false,
                false,
                cache,
            ) {
                Ok(slot) => Ok(VmMappedMemoryRegion {
                    guest_address: GuestAddress(range.start),
                    slot,
                }),
                Err(e) => Err(e),
            }
        }
        None => Err(SysError::new(EINVAL)),
    }
}

pub fn should_prepare_memory_region() -> bool {
    cfg!(target_pointer_width = "64")
}

impl FsMappingRequest {
    pub fn execute(&self, vm: &mut dyn Vm, allocator: &mut SystemAllocator) -> VmResponse {
        use self::FsMappingRequest::*;
        match *self {
            AllocateSharedMemoryRegion(alloc) => {
                match prepare_shared_memory_region(
                    vm,
                    allocator,
                    alloc,
                    MemCacheType::CacheCoherent,
                ) {
                    Ok(VmMappedMemoryRegion { slot, .. }) => VmResponse::RegisterMemory { slot },
                    Err(e) => VmResponse::Err(e),
                }
            }
            CreateMemoryMapping {
                slot,
                ref fd,
                size,
                file_offset,
                prot,
                mem_offset,
            } => match vm.add_fd_mapping(slot, mem_offset, size, fd, file_offset, prot) {
                Ok(()) => VmResponse::Ok,
                Err(e) => VmResponse::Err(e),
            },
            RemoveMemoryMapping {
                slot,
                offset,
                size,
            } => match vm.remove_mapping(slot, offset, size) {
                Ok(()) => VmResponse::Ok,
                Err(e) => VmResponse::Err(e),
            },
        }
    }
}

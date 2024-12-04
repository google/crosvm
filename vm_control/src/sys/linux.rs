// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "gpu")]
pub(crate) mod gpu;

use std::path::Path;
use std::time::Duration;

use base::error;
use base::AsRawDescriptor;
use base::Descriptor;
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
use once_cell::sync::Lazy;
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
    /// Flush the content of a memory mapping to its backing file.
    /// `slot` selects the arena (as returned by `Vm::add_mmap_arena`).
    /// `offset` is the offset of the mapping to sync within the arena.
    /// `size` is the size of the mapping to sync within the arena.
    MsyncArena {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },

    /// Gives a MADV_PAGEOUT advice to the memory region mapped at `slot`, with the address range
    /// starting at `offset` from the start of the region, and with size `size`.
    MadvisePageout {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },

    /// Gives a MADV_REMOVE advice to the memory region mapped at `slot`, with the address range
    /// starting at `offset` from the start of the region, and with size `size`.
    MadviseRemove {
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
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmMsyncResponse` with the intended purpose of sending the response back over the socket
    /// that received this `VmMsyncResponse`.
    pub fn execute(&self, vm: &mut impl Vm) -> VmMemoryMappingResponse {
        use self::VmMemoryMappingRequest::*;
        match *self {
            MsyncArena { slot, offset, size } => match vm.msync_memory_region(slot, offset, size) {
                Ok(()) => VmMemoryMappingResponse::Ok,
                Err(e) => VmMemoryMappingResponse::Err(e),
            },
            MadvisePageout { slot, offset, size } => {
                match vm.madvise_pageout_memory_region(slot, offset, size) {
                    Ok(()) => VmMemoryMappingResponse::Ok,
                    Err(e) => VmMemoryMappingResponse::Err(e),
                }
            }
            MadviseRemove { slot, offset, size } => {
                match vm.madvise_remove_memory_region(slot, offset, size) {
                    Ok(()) => VmMemoryMappingResponse::Ok,
                    Err(e) => VmMemoryMappingResponse::Err(e),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FsMappingRequest {
    /// Create an anonymous memory mapping that spans the entire region described by `Alloc`.
    AllocateSharedMemoryRegion(Alloc),
    /// Create a memory mapping.
    CreateMemoryMapping {
        /// The slot for a MemoryMappingArena, previously returned by a response to an
        /// `AllocateSharedMemoryRegion` request.
        slot: u32,
        /// The file descriptor that should be mapped.
        fd: SafeDescriptor,
        /// The size of the mapping.
        size: usize,
        /// The offset into the file from where the mapping should start.
        file_offset: u64,
        /// The memory protection to be used for the mapping.  Protections other than readable and
        /// writable will be silently dropped.
        prot: Protection,
        /// The offset into the shared memory region where the mapping should be placed.
        mem_offset: usize,
    },
    /// Remove a memory mapping.
    RemoveMemoryMapping {
        /// The slot for a MemoryMappingArena.
        slot: u32,
        /// The offset into the shared memory region.
        offset: usize,
        /// The size of the mapping.
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

static SHOULD_PREPARE_MEMORY_REGION: Lazy<bool> = Lazy::new(|| {
    if cfg!(target_arch = "x86_64") {
        // The legacy x86 MMU allocates an rmap and a page tracking array
        // that take 2.5MiB per 1GiB of user memory region address space,
        // so avoid mapping the whole shared memory region if we're not
        // using the tdp mmu.
        match std::fs::read("/sys/module/kvm/parameters/tdp_mmu") {
            Ok(bytes) if !bytes.is_empty() => bytes[0] == b'Y',
            _ => false,
        }
    } else if cfg!(target_pointer_width = "64") {
        true
    } else {
        // Not enough address space on 32-bit systems
        false
    }
});

pub fn should_prepare_memory_region() -> bool {
    *SHOULD_PREPARE_MEMORY_REGION
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
            } => {
                let raw_fd: Descriptor = Descriptor(fd.as_raw_descriptor());

                match vm.add_fd_mapping(slot, mem_offset, size, &raw_fd, file_offset, prot) {
                    Ok(()) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
            RemoveMemoryMapping { slot, offset, size } => {
                match vm.remove_mapping(slot, offset, size) {
                    Ok(()) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
        }
    }
}

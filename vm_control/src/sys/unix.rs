// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::EINVAL;
use std::{os::raw::c_int, path::Path, thread::JoinHandle};

use base::{
    error, validate_raw_descriptor, AsRawDescriptor, Descriptor, Error as SysError, Killable,
    MemoryMappingArena, MmapError, Protection, RawDescriptor, SafeDescriptor, Tube, UnixSeqpacket,
    SIGRTMIN,
};
use hypervisor::{MemSlot, Vm};
use resources::{Alloc, MmioType, SystemAllocator};
use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use crate::{
    client::{HandleRequestResult, ModifyUsbError, ModifyUsbResult},
    VmRequest, VmResponse,
};

pub(crate) fn raw_descriptor_from_path(path: &Path) -> ModifyUsbResult<RawDescriptor> {
    if !path.exists() {
        return Err(ModifyUsbError::PathDoesNotExist(path.to_owned()));
    }
    let raw_descriptor = path
        .file_name()
        .and_then(|fd_osstr| fd_osstr.to_str())
        .map_or(
            Err(ModifyUsbError::ArgParse(
                "USB_DEVICE_PATH",
                path.to_string_lossy().into_owned(),
            )),
            |fd_str| {
                fd_str.parse::<libc::c_int>().map_err(|e| {
                    ModifyUsbError::ArgParseInt("USB_DEVICE_PATH", fd_str.to_owned(), e)
                })
            },
        )?;
    validate_raw_descriptor(raw_descriptor).map_err(ModifyUsbError::FailedDescriptorValidate)
}

pub fn handle_request<T: AsRef<Path> + std::fmt::Debug>(
    request: &VmRequest,
    socket_path: T,
) -> HandleRequestResult {
    match UnixSeqpacket::connect(&socket_path) {
        Ok(s) => {
            let socket = Tube::new(s);
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
                        "failed to send request to socket at '{:?}': {}",
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
pub enum VmMsyncRequest {
    /// Flush the content of a memory mapping to its backing file.
    /// `slot` selects the arena (as returned by `Vm::add_mmap_arena`).
    /// `offset` is the offset of the mapping to sync within the arena.
    /// `size` is the size of the mapping to sync within the arena.
    MsyncArena {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMsyncResponse {
    Ok,
    Err(SysError),
}

impl VmMsyncRequest {
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmMsyncResponse` with the intended purpose of sending the response back over the socket
    /// that received this `VmMsyncResponse`.
    pub fn execute(&self, vm: &mut impl Vm) -> VmMsyncResponse {
        use self::VmMsyncRequest::*;
        match *self {
            MsyncArena { slot, offset, size } => match vm.msync_memory_region(slot, offset, size) {
                Ok(()) => VmMsyncResponse::Ok,
                Err(e) => VmMsyncResponse::Err(e),
            },
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
        prot: u32,
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

impl FsMappingRequest {
    pub fn execute(&self, vm: &mut dyn Vm, allocator: &mut SystemAllocator) -> VmResponse {
        use self::FsMappingRequest::*;
        match *self {
            AllocateSharedMemoryRegion(Alloc::PciBar {
                bus,
                dev,
                func,
                bar,
            }) => {
                match allocator
                    .mmio_allocator(MmioType::High)
                    .get(&Alloc::PciBar {
                        bus,
                        dev,
                        func,
                        bar,
                    }) {
                    Some((addr, length, _)) => {
                        let arena = match MemoryMappingArena::new(*length as usize) {
                            Ok(a) => a,
                            Err(MmapError::SystemCallFailed(e)) => return VmResponse::Err(e),
                            _ => return VmResponse::Err(SysError::new(EINVAL)),
                        };

                        match vm.add_memory_region(
                            GuestAddress(*addr),
                            Box::new(arena),
                            false,
                            false,
                        ) {
                            Ok(slot) => VmResponse::RegisterMemory {
                                pfn: addr >> 12,
                                slot,
                            },
                            Err(e) => VmResponse::Err(e),
                        }
                    }
                    None => VmResponse::Err(SysError::new(EINVAL)),
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

                match vm.add_fd_mapping(
                    slot,
                    mem_offset,
                    size,
                    &raw_fd,
                    file_offset,
                    Protection::from(prot as c_int & (libc::PROT_READ | libc::PROT_WRITE)),
                ) {
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
            _ => VmResponse::Err(SysError::new(EINVAL)),
        }
    }
}

pub(crate) fn kill_handle(handle: &JoinHandle<()>) {
    let _ = handle.kill(SIGRTMIN() + 0);
}

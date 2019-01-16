// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles IPC for controlling the main VM process.
//!
//! The VM Control IPC protocol is synchronous, meaning that each `VmRequest` sent over a connection
//! will receive a `VmResponse` for that request next time data is received over that connection.
//!
//! The wire message format is a little-endian C-struct of fixed size, along with a file descriptor
//! if the request type expects one.

extern crate byteorder;
extern crate kvm;
extern crate libc;
extern crate msg_socket;
extern crate resources;
#[macro_use]
extern crate sys_util;

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;

use libc::{EINVAL, ENODEV};

use byteorder::{LittleEndian, WriteBytesExt};
use kvm::{Datamatch, IoeventAddress, Vm};
use msg_socket::{MsgOnSocket, MsgReceiver, MsgResult, MsgSender, MsgSocket};
use resources::{GpuMemoryDesc, SystemAllocator};
use sys_util::{Error as SysError, EventFd, GuestAddress, MemoryMapping, MmapError, Result};

/// A file descriptor either borrowed or owned by this.
pub enum MaybeOwnedFd {
    /// Owned by this enum variant, and will be destructed automatically if not moved out.
    Owned(File),
    /// A file descriptor borrwed by this enum.
    Borrowed(RawFd),
}

impl AsRawFd for MaybeOwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            MaybeOwnedFd::Owned(f) => f.as_raw_fd(),
            MaybeOwnedFd::Borrowed(fd) => *fd,
        }
    }
}

// When sent, it could be owned or borrowed. On the receiver end, it always owned.
impl MsgOnSocket for MaybeOwnedFd {
    fn msg_size() -> usize {
        0usize
    }
    fn max_fd_count() -> usize {
        1usize
    }
    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        let (fd, size) = RawFd::read_from_buffer(buffer, fds)?;
        let file = File::from_raw_fd(fd);
        Ok((MaybeOwnedFd::Owned(file), size))
    }
    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        let fd = self.as_raw_fd();
        fd.write_to_buffer(buffer, fds)
    }
}

/// Mode of execution for the VM.
#[derive(Debug)]
pub enum VmRunMode {
    /// The default run mode indicating the VCPUs are running.
    Running,
    /// Indicates that the VCPUs are suspending execution until the `Running` mode is set.
    Suspending,
    /// Indicates that the VM is exiting all processes.
    Exiting,
}

impl Default for VmRunMode {
    fn default() -> Self {
        VmRunMode::Running
    }
}

/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
#[derive(MsgOnSocket)]
pub enum VmRequest {
    /// Set the size of the VM's balloon in bytes.
    BalloonAdjust(u64),
    /// Break the VM's run loop and exit.
    Exit,
    /// Suspend the VM's VCPUs until resume.
    Suspend,
    /// Resume the VM's VCPUs that were previously suspended.
    Resume,
    /// Register the given ioevent address along with given datamatch to trigger the `EventFd`.
    RegisterIoevent(EventFd, IoeventAddress, u32),
    /// Register the given IRQ number to be triggered when the `EventFd` is triggered.
    RegisterIrqfd(EventFd, u32),
    /// Register shared memory represented by the given fd into guest address space. The response
    /// variant is `VmResponse::RegisterMemory`.
    RegisterMemory(MaybeOwnedFd, usize),
    /// Unregister the given memory slot that was previously registereed with `RegisterMemory`.
    UnregisterMemory(u32),
    /// Allocate GPU buffer of a given size/format and register the memory into guest address space.
    /// The response variant is `VmResponse::AllocateAndRegisterGpuMemory`
    AllocateAndRegisterGpuMemory {
        width: u32,
        height: u32,
        format: u32,
    },
    /// Resize a disk chosen by `disk_index` to `new_size` in bytes.
    /// `disk_index` is a 0-based count of `--disk`, `--rwdisk`, and `-r` command-line options.
    DiskResize { disk_index: usize, new_size: u64 },
}

fn register_memory(
    vm: &mut Vm,
    allocator: &mut SystemAllocator,
    fd: &AsRawFd,
    size: usize,
) -> Result<(u64, u32)> {
    let mmap = match MemoryMapping::from_fd(fd, size) {
        Ok(v) => v,
        Err(MmapError::SystemCallFailed(e)) => return Err(e),
        _ => return Err(SysError::new(EINVAL)),
    };
    let addr = match allocator.allocate_device_addresses(size as u64) {
        Some(a) => a,
        None => return Err(SysError::new(EINVAL)),
    };
    let slot = match vm.add_device_memory(GuestAddress(addr), mmap, false, false) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok((addr >> 12, slot))
}

impl VmRequest {
    /// Executes this request on the given Vm and other mutable state.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    /// * `allocator` - Used to allocate addresses.
    /// * `run_mode` - Out argument that is set to a run mode if one was requested.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    pub fn execute(
        &self,
        vm: &mut Vm,
        sys_allocator: &mut SystemAllocator,
        run_mode: &mut Option<VmRunMode>,
        balloon_host_socket: &UnixDatagram,
        disk_host_sockets: &[MsgSocket<VmRequest, VmResponse>],
    ) -> VmResponse {
        match *self {
            VmRequest::Exit => {
                *run_mode = Some(VmRunMode::Exiting);
                VmResponse::Ok
            }
            VmRequest::Suspend => {
                *run_mode = Some(VmRunMode::Suspending);
                VmResponse::Ok
            }
            VmRequest::Resume => {
                *run_mode = Some(VmRunMode::Running);
                VmResponse::Ok
            }
            VmRequest::RegisterIoevent(ref evt, addr, datamatch) => {
                match vm.register_ioevent(evt, addr, Datamatch::U32(Some(datamatch))) {
                    Ok(_) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
            VmRequest::RegisterIrqfd(ref evt, irq) => match vm.register_irqfd(evt, irq) {
                Ok(_) => VmResponse::Ok,
                Err(e) => VmResponse::Err(e),
            },
            VmRequest::RegisterMemory(ref fd, size) => {
                match register_memory(vm, sys_allocator, fd, size) {
                    Ok((pfn, slot)) => VmResponse::RegisterMemory { pfn, slot },
                    Err(e) => VmResponse::Err(e),
                }
            }
            VmRequest::UnregisterMemory(slot) => match vm.remove_device_memory(slot) {
                Ok(_) => VmResponse::Ok,
                Err(e) => VmResponse::Err(e),
            },
            VmRequest::BalloonAdjust(num_pages) => {
                let mut buf = [0u8; 8];
                // write_u64 can't fail as the buffer is 8 bytes long.
                (&mut buf[0..])
                    .write_u64::<LittleEndian>(num_pages)
                    .unwrap();
                match balloon_host_socket.send(&buf) {
                    Ok(_) => VmResponse::Ok,
                    Err(_) => VmResponse::Err(SysError::last()),
                }
            }
            VmRequest::AllocateAndRegisterGpuMemory {
                width,
                height,
                format,
            } => {
                let (mut fd, desc) = match sys_allocator.gpu_memory_allocator() {
                    Some(gpu_allocator) => match gpu_allocator.allocate(width, height, format) {
                        Ok(v) => v,
                        Err(e) => return VmResponse::Err(e),
                    },
                    None => return VmResponse::Err(SysError::new(ENODEV)),
                };
                // Determine size of buffer using 0 byte seek from end. This is preferred over
                // `stride * height` as it's not limited to packed pixel formats.
                let size = match fd.seek(SeekFrom::End(0)) {
                    Ok(v) => v,
                    Err(e) => return VmResponse::Err(SysError::from(e)),
                };
                match register_memory(vm, sys_allocator, &fd, size as usize) {
                    Ok((pfn, slot)) => VmResponse::AllocateAndRegisterGpuMemory {
                        fd: MaybeOwnedFd::Owned(fd),
                        pfn,
                        slot,
                        desc,
                    },
                    Err(e) => VmResponse::Err(e),
                }
            }
            VmRequest::DiskResize {
                disk_index,
                new_size: _,
            } => {
                // Forward the request to the block device process via its control socket.
                if let Some(sock) = disk_host_sockets.get(disk_index) {
                    if let Err(e) = sock.send(self) {
                        error!("disk socket send failed: {:?}", e);
                        VmResponse::Err(SysError::new(EINVAL))
                    } else {
                        match sock.recv() {
                            Ok(result) => result,
                            Err(e) => {
                                error!("disk socket recv failed: {:?}", e);
                                VmResponse::Err(SysError::new(EINVAL))
                            }
                        }
                    }
                } else {
                    VmResponse::Err(SysError::new(ENODEV))
                }
            }
        }
    }
}

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(MsgOnSocket)]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// The request to register memory into guest address space was successfully done at page frame
    /// number `pfn` and memory slot number `slot`.
    RegisterMemory { pfn: u64, slot: u32 },
    /// The request to allocate and register GPU memory into guest address space was successfully
    /// done at page frame number `pfn` and memory slot number `slot` for buffer with `desc`.
    AllocateAndRegisterGpuMemory {
        fd: MaybeOwnedFd,
        pfn: u64,
        slot: u32,
        desc: GpuMemoryDesc,
    },
}

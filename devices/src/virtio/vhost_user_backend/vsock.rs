// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str;

use anyhow::Context;
use argh::FromArgs;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::SafeDescriptor;
use cros_async::Executor;
use data_model::Le64;
use vhost::Vhost;
use vhost::Vsock;
use vm_memory::GuestMemory;
use vmm_vhost::connection::Connection;
use vmm_vhost::message::BackendReq;
use vmm_vhost::message::VhostSharedMemoryRegion;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserInflight;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::message::VhostUserMigrationPhase;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserSingleMemoryRegion;
use vmm_vhost::message::VhostUserTransferDirection;
use vmm_vhost::message::VhostUserVringAddrFlags;
use vmm_vhost::message::VhostUserVringState;
use vmm_vhost::Error;
use vmm_vhost::Result;
use vmm_vhost::VHOST_USER_F_PROTOCOL_FEATURES;
use zerocopy::IntoBytes;

use super::BackendConnection;
use crate::virtio::device_constants::vsock::NUM_QUEUES;
use crate::virtio::vhost_user_backend::handler::vmm_va_to_gpa;
use crate::virtio::vhost_user_backend::handler::MappingInfo;
use crate::virtio::vhost_user_backend::handler::VhostUserRegularOps;
use crate::virtio::vhost_user_backend::VhostUserDeviceBuilder;
use crate::virtio::Queue;
use crate::virtio::QueueConfig;

const EVENT_QUEUE: usize = NUM_QUEUES - 1;

struct VsockBackend {
    queues: [QueueConfig; NUM_QUEUES],
    vmm_maps: Option<Vec<MappingInfo>>,
    mem: Option<GuestMemory>,

    handle: Vsock,
    cid: u64,
    protocol_features: VhostUserProtocolFeatures,
}

/// A vhost-vsock device which handle is already opened. This allows the parent process to open the
/// vhost-vsock device, create this structure, and pass it to the child process so it doesn't need
/// the rights to open the vhost-vsock device itself.
pub struct VhostUserVsockDevice {
    cid: u64,
    handle: Vsock,
}

impl VhostUserVsockDevice {
    pub fn new<P: AsRef<Path>>(cid: u64, vhost_device: P) -> anyhow::Result<Self> {
        let handle = Vsock::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(vhost_device.as_ref())
                .with_context(|| {
                    format!(
                        "failed to open vhost-vsock device {}",
                        vhost_device.as_ref().display()
                    )
                })?,
        );

        Ok(Self { cid, handle })
    }
}

impl AsRawDescriptor for VhostUserVsockDevice {
    fn as_raw_descriptor(&self) -> base::RawDescriptor {
        self.handle.as_raw_descriptor()
    }
}

impl VhostUserDeviceBuilder for VhostUserVsockDevice {
    fn build(self: Box<Self>, _ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>> {
        let backend = VsockBackend {
            queues: [
                QueueConfig::new(Queue::MAX_SIZE, 0),
                QueueConfig::new(Queue::MAX_SIZE, 0),
                QueueConfig::new(Queue::MAX_SIZE, 0),
            ],
            vmm_maps: None,
            mem: None,
            handle: self.handle,
            cid: self.cid,
            protocol_features: VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG,
        };

        Ok(Box::new(backend))
    }
}

fn convert_vhost_error(err: vhost::Error) -> Error {
    use vhost::Error::*;
    match err {
        IoctlError(e) => Error::ReqHandlerError(e),
        _ => Error::BackendInternalError,
    }
}

impl vmm_vhost::Backend for VsockBackend {
    fn set_owner(&mut self) -> Result<()> {
        self.handle.set_owner().map_err(convert_vhost_error)
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.handle.reset_owner().map_err(convert_vhost_error)
    }

    fn get_features(&mut self) -> Result<u64> {
        // Add the vhost-user features that we support.
        let features = self.handle.get_features().map_err(convert_vhost_error)?
            | 1 << VHOST_USER_F_PROTOCOL_FEATURES;
        Ok(features)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        // Unset the vhost-user feature flags as they are not supported by the underlying vhost
        // device.
        let features = features & !(1 << VHOST_USER_F_PROTOCOL_FEATURES);
        self.handle
            .set_features(features)
            .map_err(convert_vhost_error)
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        Ok(self.protocol_features)
    }

    fn set_protocol_features(&mut self, features: u64) -> Result<()> {
        let unrequested_features = features & !self.protocol_features.bits();
        if unrequested_features != 0 {
            Err(Error::InvalidParam("unsupported protocol feature"))
        } else {
            Ok(())
        }
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> Result<()> {
        let (guest_mem, vmm_maps) = VhostUserRegularOps::set_mem_table(contexts, files)?;

        self.handle
            .set_mem_table(&guest_mem)
            .map_err(convert_vhost_error)?;

        self.mem = Some(guest_mem);
        self.vmm_maps = Some(vmm_maps);

        Ok(())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        Ok(NUM_QUEUES as u64)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()> {
        if index >= NUM_QUEUES as u32 || num == 0 || num > Queue::MAX_SIZE.into() {
            return Err(Error::InvalidParam(
                "set_vring_num: vring index or size out of range",
            ));
        }

        // We checked these values already.
        let index = index as usize;
        let num = num as u16;
        self.queues[index].set_size(num);

        // The last vq is an event-only vq that is not handled by the kernel.
        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_num(index, num)
            .map_err(convert_vhost_error)
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam("set_vring_addr: index out of range"));
        }

        let index = index as usize;

        let mem = self
            .mem
            .as_ref()
            .ok_or(Error::InvalidParam("set_vring_addr: could not get mem"))?;
        let maps = self.vmm_maps.as_ref().ok_or(Error::InvalidParam(
            "set_vring_addr: could not get vmm_maps",
        ))?;

        let queue = &mut self.queues[index];
        queue.set_desc_table(vmm_va_to_gpa(maps, descriptor)?);
        queue.set_avail_ring(vmm_va_to_gpa(maps, available)?);
        queue.set_used_ring(vmm_va_to_gpa(maps, used)?);
        let log_addr = if flags.contains(VhostUserVringAddrFlags::VHOST_VRING_F_LOG) {
            vmm_va_to_gpa(maps, log).map(Some)?
        } else {
            None
        };

        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_addr(
                mem,
                queue.size(),
                index,
                flags.bits(),
                queue.desc_table(),
                queue.used_ring(),
                queue.avail_ring(),
                log_addr,
            )
            .map_err(convert_vhost_error)
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam("set_vring_base: index out of range"));
        }

        let index = index as usize;
        let base = base as u16;

        let queue = &mut self.queues[index];
        queue.set_next_avail(Wrapping(base));
        queue.set_next_used(Wrapping(base));

        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_base(index, base)
            .map_err(convert_vhost_error)
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam("get_vring_base: index out of range"));
        }

        let index = index as usize;
        let next_avail = if index == EVENT_QUEUE {
            self.queues[index].next_avail().0
        } else {
            self.handle
                .get_vring_base(index)
                .map_err(convert_vhost_error)?
        };

        Ok(VhostUserVringState::new(index as u32, next_avail.into()))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index >= NUM_QUEUES as u8 {
            return Err(Error::InvalidParam("set_vring_kick: index out of range"));
        }

        let file = fd.ok_or(Error::InvalidParam("set_vring_kick: missing fd"))?;
        let event = Event::from(SafeDescriptor::from(file));
        let index = usize::from(index);
        if index != EVENT_QUEUE {
            self.handle
                .set_vring_kick(index, &event)
                .map_err(convert_vhost_error)?;
        }

        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index >= NUM_QUEUES as u8 {
            return Err(Error::InvalidParam("set_vring_call: index out of range"));
        }

        let file = fd.ok_or(Error::InvalidParam("set_vring_call: missing fd"))?;
        let event = Event::from(SafeDescriptor::from(file));
        let index = usize::from(index);
        if index != EVENT_QUEUE {
            self.handle
                .set_vring_call(index, &event)
                .map_err(convert_vhost_error)?;
        }

        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index >= NUM_QUEUES as u8 {
            return Err(Error::InvalidParam("set_vring_err: index out of range"));
        }

        let index = usize::from(index);
        let file = fd.ok_or(Error::InvalidParam("set_vring_err: missing fd"))?;

        let event = Event::from(SafeDescriptor::from(file));

        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_err(index, &event)
            .map_err(convert_vhost_error)
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam("vring index out of range"));
        }

        self.queues[index as usize].set_ready(enable);

        if index == (EVENT_QUEUE) as u32 {
            return Ok(());
        }

        if self.queues[..EVENT_QUEUE].iter().all(|q| q.ready()) {
            // All queues are ready.  Start the device.
            self.handle.set_cid(self.cid).map_err(convert_vhost_error)?;
            self.handle.start().map_err(convert_vhost_error)
        } else if !enable {
            // If we just disabled a vring then stop the device.
            self.handle.stop().map_err(convert_vhost_error)
        } else {
            Ok(())
        }
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        let start: usize = offset
            .try_into()
            .map_err(|_| Error::InvalidParam("offset does not fit in usize"))?;
        let end: usize = offset
            .checked_add(size)
            .and_then(|e| e.try_into().ok())
            .ok_or(Error::InvalidParam("offset + size does not fit in usize"))?;

        if start >= size_of::<Le64>() || end > size_of::<Le64>() {
            return Err(Error::InvalidParam(
                "get_config: offset and/or size out of range",
            ));
        }

        Ok(Le64::from(self.cid).as_bytes()[start..end].to_vec())
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn set_backend_req_fd(&mut self, _vu_req: Connection<BackendReq>) {
        // We didn't set VhostUserProtocolFeatures::BACKEND_REQ
        unreachable!("unexpected set_backend_req_fd");
    }

    fn get_inflight_fd(
        &mut self,
        _inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        Err(Error::InvalidOperation)
    }

    fn set_inflight_fd(&mut self, _inflight: &VhostUserInflight, _file: File) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        Err(Error::InvalidOperation)
    }

    fn add_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion, _fd: File) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn remove_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn set_device_state_fd(
        &mut self,
        _transfer_direction: VhostUserTransferDirection,
        _migration_phase: VhostUserMigrationPhase,
        _fd: File,
    ) -> Result<Option<File>> {
        Err(Error::InvalidOperation)
    }

    fn check_device_state(&mut self) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>> {
        Ok(vec![])
    }
}

#[derive(FromArgs)]
#[argh(subcommand, name = "vsock")]
/// Vsock device
pub struct Options {
    #[argh(option, arg_name = "PATH", hidden_help)]
    /// deprecated - please use --socket-path instead
    socket: Option<String>,
    #[argh(option, arg_name = "PATH")]
    /// path to the vhost-user socket to bind to.
    /// If this flag is set, --fd cannot be specified.
    socket_path: Option<String>,
    #[argh(option, arg_name = "FD")]
    /// file descriptor of a connected vhost-user socket.
    /// If this flag is set, --socket-path cannot be specified.
    fd: Option<RawDescriptor>,

    #[argh(option, arg_name = "INT")]
    /// the vsock context id for this device
    cid: u64,
    #[argh(
        option,
        default = "String::from(\"/dev/vhost-vsock\")",
        arg_name = "PATH"
    )]
    /// path to the vhost-vsock control socket
    vhost_socket: String,
}

/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_vsock_device(opts: Options) -> anyhow::Result<()> {
    let ex = Executor::new().context("failed to create executor")?;

    let conn =
        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;

    let vsock_device = Box::new(VhostUserVsockDevice::new(opts.cid, opts.vhost_socket)?);

    conn.run_device(ex, vsock_device)
}

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert;
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::str;
use std::sync::Mutex as StdMutex;

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::Event;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::UnlinkUnixListener;
use cros_async::EventAsync;
use cros_async::Executor;
use data_model::Le64;
use vhost::Vhost;
use vhost::Vsock;
use vm_memory::GuestMemory;
use vmm_vhost::connection::vfio::Listener as VfioListener;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::message::SlaveReq;
use vmm_vhost::message::VhostSharedMemoryRegion;
use vmm_vhost::message::VhostUserConfigFlags;
use vmm_vhost::message::VhostUserInflight;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserSingleMemoryRegion;
use vmm_vhost::message::VhostUserVirtioFeatures;
use vmm_vhost::message::VhostUserVringAddrFlags;
use vmm_vhost::message::VhostUserVringState;
use vmm_vhost::Error;
use vmm_vhost::Protocol;
use vmm_vhost::Result;
use vmm_vhost::SlaveListener;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandlerMut;
use zerocopy::AsBytes;

use crate::virtio::device_constants::vsock::NUM_QUEUES;
use crate::virtio::device_constants::vsock::QUEUE_SIZE;
use crate::virtio::vhost::user::device::handler::sys::unix::run_handler;
// TODO(acourbot) try to remove the system dependencies and make the device usable on all platforms.
use crate::virtio::vhost::user::device::handler::sys::unix::Doorbell;
use crate::virtio::vhost::user::device::handler::sys::unix::VvuOps;
use crate::virtio::vhost::user::device::handler::vmm_va_to_gpa;
use crate::virtio::vhost::user::device::handler::MappingInfo;
use crate::virtio::vhost::user::device::handler::VhostUserPlatformOps;
use crate::virtio::vhost::user::device::handler::VhostUserRegularOps;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;
use crate::virtio::vhost::user::device::vvu::VvuDevice;
use crate::virtio::Queue;
use crate::virtio::SignalableInterrupt;

const MAX_VRING_LEN: u16 = QUEUE_SIZE;
const EVENT_QUEUE: usize = NUM_QUEUES - 1;

struct VsockBackend {
    queues: [Queue; NUM_QUEUES],
    vmm_maps: Option<Vec<MappingInfo>>,
    mem: Option<GuestMemory>,
    ops: Box<dyn VhostUserPlatformOps>,

    ex: Executor,
    handle: Vsock,
    cid: u64,
    protocol_features: VhostUserProtocolFeatures,
}

impl VsockBackend {
    fn new<P: AsRef<Path>>(
        ex: &Executor,
        cid: u64,
        vhost_socket: P,
        ops: Box<dyn VhostUserPlatformOps>,
    ) -> anyhow::Result<VsockBackend> {
        let handle = Vsock::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(vhost_socket)
                .context("failed to open `Vsock` socket")?,
        );

        let protocol_features = VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;
        Ok(VsockBackend {
            queues: [
                Queue::new(MAX_VRING_LEN),
                Queue::new(MAX_VRING_LEN),
                Queue::new(MAX_VRING_LEN),
            ],
            vmm_maps: None,
            mem: None,
            ops,
            ex: ex.clone(),
            handle,
            cid,
            protocol_features,
        })
    }
}

fn convert_vhost_error(err: vhost::Error) -> Error {
    use vhost::Error::*;
    match err {
        IoctlError(e) => Error::ReqHandlerError(e),
        _ => Error::SlaveInternalError,
    }
}

impl VhostUserSlaveReqHandlerMut for VsockBackend {
    fn protocol(&self) -> Protocol {
        self.ops.protocol()
    }

    fn set_owner(&mut self) -> Result<()> {
        self.handle.set_owner().map_err(convert_vhost_error)
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.handle.reset_owner().map_err(convert_vhost_error)
    }

    fn get_features(&mut self) -> Result<u64> {
        // Add the vhost-user features that we support.
        let features = self.handle.get_features().map_err(convert_vhost_error)?
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        Ok(features)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        // Unset the vhost-user feature flags as they are not supported by the underlying vhost
        // device.
        let features = features & !VhostUserVirtioFeatures::all().bits();
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
            Err(Error::InvalidParam)
        } else {
            Ok(())
        }
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> Result<()> {
        let (guest_mem, vmm_maps) = self.ops.set_mem_table(contexts, files)?;

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
        if index >= NUM_QUEUES as u32 || num == 0 || num > QUEUE_SIZE.into() {
            return Err(Error::InvalidParam);
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
            return Err(Error::InvalidParam);
        }

        let index = index as usize;

        let mem = self.mem.as_ref().ok_or(Error::InvalidParam)?;
        let maps = self.vmm_maps.as_ref().ok_or(Error::InvalidParam)?;

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
                queue.max_size(),
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
        if index >= NUM_QUEUES as u32 || base >= QUEUE_SIZE.into() {
            return Err(Error::InvalidParam);
        }

        let index = index as usize;
        let base = base as u16;

        let mut queue = &mut self.queues[index];
        queue.next_avail = Wrapping(base);
        queue.next_used = Wrapping(base);

        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_base(index, base)
            .map_err(convert_vhost_error)
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam);
        }

        let index = index as usize;
        let next_avail = if index == EVENT_QUEUE {
            self.queues[index].next_avail.0
        } else {
            self.handle
                .get_vring_base(index)
                .map_err(convert_vhost_error)?
        };

        Ok(VhostUserVringState::new(index as u32, next_avail.into()))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index >= NUM_QUEUES as u8 {
            return Err(Error::InvalidParam);
        }

        let event = self.ops.set_vring_kick(index, fd)?;
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
            return Err(Error::InvalidParam);
        }

        let doorbell = self.ops.set_vring_call(index, fd)?;
        let index = usize::from(index);
        let event = match doorbell {
            Doorbell::Call(call_event) => call_event.into_inner(),
            Doorbell::Vfio(doorbell_region) => {
                let kernel_evt = Event::new().map_err(|_| Error::SlaveInternalError)?;
                let task_evt = EventAsync::new(
                    kernel_evt.try_clone().expect("failed to clone event"),
                    &self.ex,
                )
                .map_err(|_| Error::SlaveInternalError)?;
                self.ex
                    .spawn_local(async move {
                        loop {
                            let _ = task_evt
                                .next_val()
                                .await
                                .expect("failed to wait for event fd");
                            doorbell_region.signal_used_queue(index as u16);
                        }
                    })
                    .detach();
                kernel_evt
            }
        };
        if index != EVENT_QUEUE {
            self.handle
                .set_vring_call(index, &event)
                .map_err(convert_vhost_error)?;
        }

        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        if index >= NUM_QUEUES as u8 {
            return Err(Error::InvalidParam);
        }

        let index = usize::from(index);
        let file = fd.ok_or(Error::InvalidParam)?;

        // Safe because the descriptor is uniquely owned by `file`.
        let event = unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) };

        if index == EVENT_QUEUE {
            return Ok(());
        }

        self.handle
            .set_vring_err(index, &event)
            .map_err(convert_vhost_error)
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        if index >= NUM_QUEUES as u32 {
            return Err(Error::InvalidParam);
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
        let start: usize = offset.try_into().map_err(|_| Error::InvalidParam)?;
        let end: usize = offset
            .checked_add(size)
            .and_then(|e| e.try_into().ok())
            .ok_or(Error::InvalidParam)?;

        if start >= size_of::<Le64>() || end > size_of::<Le64>() {
            return Err(Error::InvalidParam);
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

    fn set_slave_req_fd(&mut self, _vu_req: Box<dyn Endpoint<SlaveReq>>) {
        // We didn't set VhostUserProtocolFeatures::SLAVE_REQ
        unreachable!("unexpected set_slave_req_fd");
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

    fn get_shared_memory_regions(&mut self) -> Result<Vec<VhostSharedMemoryRegion>> {
        Ok(vec![])
    }
}

async fn run_device<P: AsRef<Path>>(
    ex: &Executor,
    socket: P,
    backend: StdMutex<VsockBackend>,
) -> anyhow::Result<()> {
    let listener = UnixListener::bind(socket)
        .map(UnlinkUnixListener)
        .context("failed to bind socket")?;
    let (socket, _) = ex
        .spawn_blocking(move || listener.accept())
        .await
        .context("failed to accept socket connection")?;

    let req_handler = SlaveReqHandler::from_stream(socket, backend);

    ex.run_until(run_handler(req_handler, ex))?
}

#[derive(FromArgs)]
#[argh(subcommand, name = "vsock")]
/// Vsock device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to bind a listening vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// name of vfio pci device
    vfio: Option<String>,
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

fn run_vvu_device<P: AsRef<Path>>(
    ex: &Executor,
    cid: u64,
    vhost_socket: P,
    device_name: &str,
) -> anyhow::Result<()> {
    let mut device =
        VvuPciDevice::new(device_name, NUM_QUEUES).context("failed to create `VvuPciDevice`")?;
    let backend = VsockBackend::new(ex, cid, vhost_socket, Box::new(VvuOps::new(&mut device)))
        .map(StdMutex::new)
        .context("failed to create `VsockBackend`")?;
    let driver = VvuDevice::new(device);

    let mut listener = VfioListener::new(driver)
        .context("failed to create `VfioListener`")
        .and_then(|l| {
            SlaveListener::<VfioListener<_>, _>::new(l, backend)
                .context("failed to create `SlaveListener`")
        })?;
    let req_handler = listener
        .accept()
        .context("failed to accept vfio connection")?
        .expect("no incoming connection detected");

    match ex.run_until(run_handler(req_handler, ex)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e).context("executor error"),
    }
}

/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_vsock_device(opts: Options) -> anyhow::Result<()> {
    let ex = Executor::new().context("failed to create executor")?;

    match (opts.socket, opts.vfio) {
        (Some(socket), None) => {
            let backend = VsockBackend::new(
                &ex,
                opts.cid,
                opts.vhost_socket,
                Box::new(VhostUserRegularOps),
            )
            .map(StdMutex::new)?;

            // TODO: Replace the `and_then` with `Result::flatten` once it is stabilized.
            ex.run_until(run_device(&ex, socket, backend))
                .context("failed to run vsock device")
                .and_then(convert::identity)
        }
        (None, Some(device_name)) => run_vvu_device(&ex, opts.cid, opts.vhost_socket, &device_name),
        _ => bail!("Exactly one of `--socket` or `--vfio` is required"),
    }
}

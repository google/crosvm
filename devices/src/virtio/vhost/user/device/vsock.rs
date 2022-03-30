// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::fs::OpenOptionsExt;
use std::{
    convert::{self, TryFrom, TryInto},
    fs::{File, OpenOptions},
    mem::size_of,
    num::Wrapping,
    os::unix::net::UnixListener,
    path::Path,
    str,
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{bail, Context};
use argh::FromArgs;
use base::{
    clear_fd_flags, error, info, AsRawDescriptor, Event, FromRawDescriptor, IntoRawDescriptor,
    SafeDescriptor, UnlinkUnixListener,
};
use cros_async::{AsyncWrapper, EventAsync, Executor};
use data_model::{DataInit, Le64};
use hypervisor::ProtectionType;
use sync::Mutex;
use vhost::{self, Vhost, Vsock};
use vm_memory::GuestMemory;
use vmm_vhost::{
    connection::vfio::{Endpoint as VfioEndpoint, Listener as VfioListener},
    message::{
        VhostUserConfigFlags, VhostUserInflight, VhostUserMemoryRegion, VhostUserProtocolFeatures,
        VhostUserSingleMemoryRegion, VhostUserVirtioFeatures, VhostUserVringAddrFlags,
        VhostUserVringState,
    },
    Error, Result, SlaveReqHandler, VhostUserSlaveReqHandlerMut,
};
use vmm_vhost::{Protocol, SlaveListener};

use crate::{
    vfio::VfioRegionAddr,
    virtio::{
        base_features,
        vhost::{
            user::device::{
                handler::{
                    create_guest_memory, create_vvu_guest_memory, vmm_va_to_gpa, HandlerType,
                    MappingInfo,
                },
                vvu::{doorbell::DoorbellRegion, pci::VvuPciDevice, VvuDevice},
            },
            vsock,
        },
        Queue, SignalableInterrupt,
    },
};

const MAX_VRING_LEN: u16 = vsock::QUEUE_SIZE;
const NUM_QUEUES: usize = vsock::QUEUE_SIZES.len();
const EVENT_QUEUE: usize = NUM_QUEUES - 1;

struct VsockBackend {
    ex: Executor,
    handle: Vsock,
    cid: u64,
    features: u64,
    handler_type: HandlerType,
    protocol_features: VhostUserProtocolFeatures,
    mem: Option<GuestMemory>,
    vmm_maps: Option<Vec<MappingInfo>>,
    queues: [Queue; NUM_QUEUES],
    // Only used for vvu device mode.
    call_evts: [Option<Arc<Mutex<DoorbellRegion>>>; NUM_QUEUES],
}

impl VsockBackend {
    fn new<P: AsRef<Path>>(
        ex: &Executor,
        cid: u64,
        vhost_socket: P,
        handler_type: HandlerType,
    ) -> anyhow::Result<VsockBackend> {
        let handle = Vsock::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(vhost_socket)
                .context("failed to open `Vsock` socket")?,
        );

        let features = handle.get_features().context("failed to get features")?;
        let protocol_features = VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;
        Ok(VsockBackend {
            ex: ex.clone(),
            handle,
            cid,
            features,
            handler_type,
            protocol_features,
            mem: None,
            vmm_maps: None,
            queues: [
                Queue::new(MAX_VRING_LEN),
                Queue::new(MAX_VRING_LEN),
                Queue::new(MAX_VRING_LEN),
            ],
            call_evts: Default::default(),
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
        match self.handler_type {
            HandlerType::VhostUser => Protocol::Regular,
            HandlerType::Vvu { .. } => Protocol::Virtio,
        }
    }

    fn set_owner(&mut self) -> Result<()> {
        self.handle.set_owner().map_err(convert_vhost_error)
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.handle.reset_owner().map_err(convert_vhost_error)
    }

    fn get_features(&mut self) -> Result<u64> {
        let features = base_features(ProtectionType::Unprotected)
            | self.features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        Ok(features)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        self.handle
            .set_features(features & self.features)
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
        let (guest_mem, vmm_maps) = match &self.handler_type {
            HandlerType::VhostUser => create_guest_memory(contexts, files)?,
            HandlerType::Vvu { vfio_dev, caps, .. } => {
                // virtio-vhost-user doesn't pass FDs.
                if !files.is_empty() {
                    return Err(Error::InvalidParam);
                }
                create_vvu_guest_memory(vfio_dev.as_ref(), caps.shared_mem_cfg_addr(), contexts)?
            }
        };

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
        if index >= NUM_QUEUES as u32 || num == 0 || num > vsock::QUEUE_SIZE.into() {
            return Err(Error::InvalidParam);
        }

        // We checked these values already.
        let index = index as usize;
        let num = num as u16;
        self.queues[index].size = num;

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

        let mut queue = &mut self.queues[index];
        queue.desc_table = vmm_va_to_gpa(maps, descriptor)?;
        queue.avail_ring = vmm_va_to_gpa(maps, available)?;
        queue.used_ring = vmm_va_to_gpa(maps, used)?;
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
                queue.max_size,
                queue.actual_size(),
                index,
                flags.bits(),
                queue.desc_table,
                queue.used_ring,
                queue.avail_ring,
                log_addr,
            )
            .map_err(convert_vhost_error)
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        if index >= NUM_QUEUES as u32 || base >= vsock::QUEUE_SIZE.into() {
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

        let index = usize::from(index);
        let event = match &self.handler_type {
            HandlerType::Vvu {
                notification_evts, ..
            } => {
                if fd.is_some() {
                    return Err(Error::InvalidParam);
                }
                let queue = &mut self.queues[index];
                if queue.ready {
                    error!("kick fd cannot replaced after queue is started");
                    return Err(Error::InvalidOperation);
                }

                notification_evts[index].try_clone().map_err(|e| {
                    error!("failed to clone notification_evts[{}]: {}", index, e);
                    Error::InvalidOperation
                })?
            }
            HandlerType::VhostUser => {
                let file = fd.ok_or(Error::InvalidParam)?;

                // Safe because the descriptor is uniquely owned by `file`.
                let event = unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) };

                // Remove O_NONBLOCK from the kick fd.
                if let Err(e) = clear_fd_flags(event.as_raw_descriptor(), libc::O_NONBLOCK) {
                    error!("failed to remove O_NONBLOCK for kick fd: {}", e);
                    return Err(Error::InvalidParam);
                }

                event
            }
        };

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

        let index = usize::from(index);
        let event = match &self.handler_type {
            HandlerType::Vvu { vfio_dev, caps, .. } => {
                let vfio = Arc::clone(vfio_dev);
                let base = caps.doorbell_base_addr();
                let addr = VfioRegionAddr {
                    index: base.index,
                    addr: base.addr + (index as u64 * caps.doorbell_off_multiplier() as u64),
                };

                let doorbell = DoorbellRegion {
                    vfio,
                    index: index as u8,
                    addr,
                };
                let call_evt = match self.call_evts[index].as_ref() {
                    None => {
                        let evt = Arc::new(Mutex::new(doorbell));
                        self.call_evts[index] = Some(evt.clone());
                        evt
                    }
                    Some(evt) => {
                        *evt.lock() = doorbell;
                        evt.clone()
                    }
                };

                let kernel_evt = Event::new().map_err(|_| Error::SlaveInternalError)?;
                let task_evt = EventAsync::new(
                    kernel_evt.try_clone().expect("failed to clone event").0,
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
                            call_evt.signal_used_queue(index as u16);
                        }
                    })
                    .detach();
                kernel_evt
            }
            HandlerType::VhostUser => {
                let file = fd.ok_or(Error::InvalidParam)?;
                // Safe because the descriptor is uniquely owned by `file`.
                unsafe { Event::from_raw_descriptor(file.into_raw_descriptor()) }
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

        self.queues[index as usize].ready = enable;

        if index == (EVENT_QUEUE) as u32 {
            return Ok(());
        }

        if self.queues[..EVENT_QUEUE].iter().all(|q| q.ready) {
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

        Ok(Le64::from(self.cid).as_slice()[start..end].to_vec())
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> Result<()> {
        Err(Error::InvalidOperation)
    }

    fn set_slave_req_fd(&mut self, _vu_req: File) {}

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
}

async fn run_device<P: AsRef<Path>>(
    ex: &Executor,
    socket: P,
    backend: Arc<StdMutex<VsockBackend>>,
) -> anyhow::Result<()> {
    let listener = UnixListener::bind(socket)
        .map(UnlinkUnixListener)
        .context("failed to bind socket")?;
    let (socket, _) = ex
        .spawn_blocking(move || listener.accept())
        .await
        .context("failed to accept socket connection")?;

    let mut req_handler = SlaveReqHandler::from_stream(socket, backend);
    let h = SafeDescriptor::try_from(&req_handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .expect("failed to get safe descriptor for handler");
    let handler_source = ex.async_from(h).context("failed to create async handler")?;

    loop {
        handler_source
            .wait_readable()
            .await
            .context("failed to wait for vhost socket to become readable")?;
        match req_handler.handle_request() {
            Ok(()) => (),
            Err(Error::Disconnect) => {
                info!("vhost-user connection closed");
                // Exit as the client closed the connection.
                return Ok(());
            }
            Err(e) => {
                bail!("failed to handle a vhost-user request: {}", e);
            }
        };
    }
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(
        option,
        description = "path to bind a listening vhost-user socket",
        arg_name = "PATH"
    )]
    socket: Option<String>,
    #[argh(option, description = "name of vfio pci device", arg_name = "STRING")]
    vfio: Option<String>,
    #[argh(
        option,
        description = "the vsock context id for this device",
        arg_name = "INT"
    )]
    cid: u64,
    #[argh(
        option,
        description = "path to the vhost-vsock control socket",
        default = "String::from(\"/dev/vhost-vsock\")",
        arg_name = "PATH"
    )]
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
    let backend = VsockBackend::new(
        ex,
        cid,
        vhost_socket,
        HandlerType::Vvu {
            vfio_dev: Arc::clone(&device.vfio_dev),
            caps: device.caps.clone(),
            notification_evts: std::mem::take(&mut device.notification_evts),
        },
    )
    .map(StdMutex::new)
    .map(Arc::new)
    .context("failed to create `VsockBackend`")?;
    let driver = VvuDevice::new(device);

    let mut listener = VfioListener::new(driver)
        .context("failed to create `VfioListener`")
        .and_then(|l| {
            SlaveListener::<VfioEndpoint<_, _>, _>::new(l, backend)
                .context("failed to create `SlaveListener`")
        })?;
    let mut req_handler = listener
        .accept()
        .context("failed to accept vfio connection")?
        .expect("no incoming connection detected");
    let h = SafeDescriptor::try_from(&req_handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .expect("failed to get safe descriptor for handler");
    let handler_source = ex
        .async_from(h)
        .context("failed to create async handler source")?;

    let done = async move {
        loop {
            let count = handler_source
                .read_u64()
                .await
                .context("failed to wait for handler source")?;
            for _ in 0..count {
                req_handler
                    .handle_request()
                    .context("failed to handle request")?;
            }
        }
    };
    match ex.run_until(done) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e).context("executor error"),
    }
}

/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_vsock_device(program_name: &str, args: &[&str]) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    let ex = Executor::new().context("failed to create executor")?;

    match (opts.socket, opts.vfio) {
        (Some(socket), None) => {
            let backend =
                VsockBackend::new(&ex, opts.cid, opts.vhost_socket, HandlerType::VhostUser)
                    .map(StdMutex::new)
                    .map(Arc::new)?;

            // TODO: Replace the `and_then` with `Result::flatten` once it is stabilized.
            ex.run_until(run_device(&ex, socket, backend))
                .context("failed to run vsock device")
                .and_then(convert::identity)
        }
        (None, Some(device_name)) => run_vvu_device(&ex, opts.cid, opts.vhost_socket, &device_name),
        _ => bail!("Exactly one of `--socket` or `--vfio` is required"),
    }
}

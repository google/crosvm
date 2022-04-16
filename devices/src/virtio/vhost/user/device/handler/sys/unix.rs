// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use anyhow::{Context, Result};
use base::{clear_fd_flags, error, info, AsRawDescriptor, Event, SafeDescriptor};
use cros_async::{AsyncWrapper, Executor};
use vm_memory::GuestMemory;
use vmm_vhost::{
    connection::{
        socket::Listener as SocketListener,
        vfio::{Endpoint as VfioEndpoint, Listener as VfioListener},
        Endpoint, Listener,
    },
    message::{MasterReq, VhostUserMemoryRegion},
    Error as VhostError, Protocol, Result as VhostResult, SlaveListener, SlaveReqHandler,
    VhostUserSlaveReqHandler,
};

use crate::vfio::{VfioDevice, VfioRegionAddr};
use crate::virtio::interrupt::SignalableInterrupt;
use crate::virtio::vhost::user::device::handler::{
    DeviceRequestHandler, Doorbell, GuestAddress, HandlerType, MappingInfo, MemoryRegion,
    VhostUserBackend,
};
use crate::virtio::vhost::user::device::vvu::{
    device::VvuDevice,
    doorbell::DoorbellRegion,
    pci::{VvuPciCaps, VvuPciDevice},
};

pub(crate) enum HandlerTypeSys {
    Vvu {
        vfio_dev: Arc<VfioDevice>,
        caps: VvuPciCaps,
        notification_evts: Vec<Event>,
    },
}

pub enum DoorbellSys {
    Vfio(DoorbellRegion),
}

pub(crate) fn create_vvu_guest_memory(
    vfio_dev: &VfioDevice,
    shared_mem_addr: &VfioRegionAddr,
    contexts: &[VhostUserMemoryRegion],
) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
    let file_offset = vfio_dev.get_offset_for_addr(shared_mem_addr).map_err(|e| {
        error!("failed to get underlying file: {}", e);
        VhostError::InvalidOperation
    })?;

    let mut vmm_maps = Vec::with_capacity(contexts.len());
    let mut regions = Vec::with_capacity(contexts.len());
    let page_size = base::pagesize() as u64;
    for region in contexts {
        let offset = file_offset + region.mmap_offset;
        assert_eq!(offset % page_size, 0);

        vmm_maps.push(MappingInfo {
            vmm_addr: region.user_addr as u64,
            guest_phys: region.guest_phys_addr as u64,
            size: region.memory_size,
        });

        let cloned_file = vfio_dev.dev_file().try_clone().map_err(|e| {
            error!("failed to clone vfio device file: {}", e);
            VhostError::InvalidOperation
        })?;
        let region = MemoryRegion::new_from_file(
            region.memory_size,
            GuestAddress(region.guest_phys_addr),
            file_offset + region.mmap_offset,
            Arc::new(cloned_file),
        )
        .map_err(|e| {
            error!("failed to create a memory region: {}", e);
            VhostError::InvalidOperation
        })?;
        regions.push(region);
    }

    let guest_mem = GuestMemory::from_regions(regions).map_err(|e| {
        error!("failed to create guest memory: {}", e);
        VhostError::InvalidOperation
    })?;

    Ok((guest_mem, vmm_maps))
}

pub(in crate::virtio::vhost::user::device::handler) fn system_protocol(
    handler_type: &HandlerTypeSys,
) -> Protocol {
    match handler_type {
        HandlerTypeSys::Vvu { .. } => Protocol::Virtio,
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_set_mem_table(
    handler_type_sys: &HandlerTypeSys,
    files: Vec<File>,
    contexts: &[VhostUserMemoryRegion],
) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
    match handler_type_sys {
        HandlerTypeSys::Vvu {
            vfio_dev: device,
            caps,
            ..
        } => {
            // virtio-vhost-user doesn't pass FDs.
            if !files.is_empty() {
                return Err(VhostError::InvalidParam);
            }
            Ok(create_vvu_guest_memory(
                device.as_ref(),
                caps.shared_mem_cfg_addr(),
                contexts,
            )?)
        }
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_get_kick_evt(
    handler_type_sys: &HandlerTypeSys,
    index: u8,
    file: Option<File>,
) -> VhostResult<Event> {
    match handler_type_sys {
        HandlerTypeSys::Vvu {
            notification_evts, ..
        } => {
            if file.is_some() {
                return Err(VhostError::InvalidParam);
            }
            Ok(notification_evts[index as usize].try_clone().map_err(|e| {
                error!("failed to clone notification_evts[{}]: {}", index, e);
                VhostError::InvalidOperation
            })?)
        }
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_create_doorbell(
    handler_type_sys: &HandlerTypeSys,
    index: u8,
) -> VhostResult<Doorbell> {
    match handler_type_sys {
        HandlerTypeSys::Vvu {
            vfio_dev: device,
            caps,
            ..
        } => {
            let base = caps.doorbell_base_addr();
            let addr = VfioRegionAddr {
                index: base.index,
                addr: base.addr + (index as u64 * caps.doorbell_off_multiplier() as u64),
            };
            Ok(Doorbell::SystemDoorbell(DoorbellSys::Vfio(
                DoorbellRegion {
                    vfio: Arc::clone(device),
                    index,
                    addr,
                },
            )))
        }
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_clear_rd_flags(
    file: &File,
) -> VhostResult<()> {
    // Remove O_NONBLOCK from kick_fd. Otherwise, uring_executor will fails when we read
    // values via `next_val()` later.
    if let Err(e) = clear_fd_flags(file.as_raw_fd(), libc::O_NONBLOCK) {
        error!("failed to remove O_NONBLOCK for kick fd: {}", e);
        return Err(VhostError::InvalidParam);
    }
    Ok(())
}

pub(in crate::virtio::vhost::user::device::handler) fn system_signal_config_changed(
    doorbell_sys: &DoorbellSys,
) {
    match doorbell_sys {
        DoorbellSys::Vfio(evt) => evt.signal_config_changed(),
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_get_resample_evt(
    doorbell_sys: &DoorbellSys,
) -> Option<&Event> {
    match doorbell_sys {
        DoorbellSys::Vfio(evt) => evt.get_resample_evt(),
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_do_interrupt_resample(
    doorbell_sys: &DoorbellSys,
) {
    match doorbell_sys {
        DoorbellSys::Vfio(evt) => evt.do_interrupt_resample(),
    }
}

pub(in crate::virtio::vhost::user::device::handler) fn system_signal(
    doorbell_sys: &DoorbellSys,
    vector: u16,
    interrupt_status_mask: u32,
) {
    match doorbell_sys {
        DoorbellSys::Vfio(evt) => evt.signal(vector, interrupt_status_mask),
    }
}

/// Performs the run loop for an already-constructor request handler.
pub async fn run_handler<S, E>(mut req_handler: SlaveReqHandler<S, E>, ex: &Executor) -> Result<()>
where
    S: VhostUserSlaveReqHandler,
    E: Endpoint<MasterReq> + AsRawDescriptor,
{
    let h = SafeDescriptor::try_from(&req_handler as &dyn AsRawDescriptor)
        .map(AsyncWrapper::new)
        .context("failed to get safe descriptor for handler")?;
    let handler_source = ex
        .async_from(h)
        .context("failed to create an async source")?;

    loop {
        handler_source
            .wait_readable()
            .await
            .context("failed to wait for the handler to become readable")?;
        match req_handler.handle_request() {
            Ok(()) => (),
            Err(VhostError::ClientExit) => {
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

impl<B> DeviceRequestHandler<B>
where
    B: 'static + VhostUserBackend,
{
    /// Creates a listening socket at `socket` and handles incoming messages from the VMM, which are
    /// dispatched to the device backend via the `VhostUserBackend` trait methods.
    pub async fn run<P: AsRef<Path>>(self, socket: P, ex: &Executor) -> Result<()> {
        let listener = SocketListener::new(socket, true /* unlink */)
            .context("failed to create a socket listener")?;
        return self.run_with_listener(listener, ex).await;
    }

    /// Attaches to an already bound socket via `listener` and handles incoming messages from the
    /// VMM, which are dispatched to the device backend via the `VhostUserBackend` trait methods.
    pub async fn run_with_listener(
        self,
        mut listener: SocketListener,
        ex: &Executor,
    ) -> Result<()> {
        let socket = ex
            .spawn_blocking(move || {
                listener
                    .accept()
                    .context("failed to accept an incoming connection")
            })
            .await?
            .ok_or(anyhow!("failed to accept an incoming connection"))?;
        let req_handler = SlaveReqHandler::from_stream(socket, std::sync::Mutex::new(self));

        run_handler(req_handler, ex).await
    }

    /// Starts listening virtio-vhost-user device with VFIO to handle incoming vhost-user messages
    /// forwarded by it.
    pub async fn run_vvu(mut self, mut device: VvuPciDevice, ex: &Executor) -> Result<()> {
        self.handler_type = HandlerType::SystemHandlerType(HandlerTypeSys::Vvu {
            vfio_dev: Arc::clone(&device.vfio_dev),
            caps: device.caps.clone(),
            notification_evts: std::mem::take(&mut device.notification_evts),
        });
        let driver = VvuDevice::new(device);

        let mut listener = VfioListener::new(driver)
            .map_err(|e| anyhow!("failed to create a VFIO listener: {}", e))
            .and_then(|l| {
                SlaveListener::<VfioEndpoint<_, _>, _>::new(l, std::sync::Mutex::new(self))
                    .map_err(|e| anyhow!("failed to create SlaveListener: {}", e))
            })?;

        let req_handler = listener
            .accept()
            .map_err(|e| anyhow!("failed to accept VFIO connection: {}", e))?
            .expect("vvu proxy is unavailable via VFIO");

        run_handler(req_handler, ex).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::mpsc::channel;
    use std::sync::Barrier;

    use crate::virtio::vhost::user::device::handler::tests::*;
    use crate::virtio::vhost::user::device::handler::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;

    use tempfile::{Builder, TempDir};

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn test_vhost_user_activate() {
        use vmm_vhost::{
            connection::socket::{Endpoint as SocketEndpoint, Listener as SocketListener},
            SlaveListener,
        };

        const QUEUES_NUM: usize = 2;

        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let listener = SocketListener::new(&path, true).unwrap();

        let vmm_bar = Arc::new(Barrier::new(2));
        let dev_bar = vmm_bar.clone();

        let (tx, rx) = channel();

        std::thread::spawn(move || {
            // VMM side
            rx.recv().unwrap(); // Ensure the device is ready.

            let allow_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
            let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;
            let mut vmm_handler = VhostUserHandler::new_from_path(
                &path,
                QUEUES_NUM as u64,
                allow_features,
                init_features,
                allow_protocol_features,
            )
            .unwrap();

            vmm_handler_send_requests(&mut vmm_handler, QUEUES_NUM);

            // The VMM side is supposed to stop before the device side.
            drop(vmm_handler);

            vmm_bar.wait();
        });

        // Device side
        let handler = std::sync::Mutex::new(DeviceRequestHandler::new(FakeBackend::new()));
        let mut listener = SlaveListener::<SocketEndpoint<_>, _>::new(listener, handler).unwrap();

        // Notify listener is ready.
        tx.send(()).unwrap();

        let mut listener = listener.accept().unwrap().unwrap();

        test_handle_requests(&mut listener, QUEUES_NUM);

        dev_bar.wait();

        match listener.handle_request() {
            Err(VhostError::ClientExit) => (),
            r => panic!("Err(ClientExit) was expected but {:?}", r),
        }
    }
}

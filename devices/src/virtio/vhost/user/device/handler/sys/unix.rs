// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Event;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vm_memory::GuestMemory;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::connection::Listener;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Protocol;
use vmm_vhost::Result as VhostResult;
use vmm_vhost::SlaveListener;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandler;

use crate::vfio::VfioDevice;
use crate::virtio::vhost::user::device::handler::CallEvent;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::handler::GuestAddress;
use crate::virtio::vhost::user::device::handler::MappingInfo;
use crate::virtio::vhost::user::device::handler::MemoryRegion;
use crate::virtio::vhost::user::device::handler::VhostUserPlatformOps;
use crate::virtio::vhost::user::device::vvu::doorbell::DoorbellRegion;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciCaps;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;
use crate::virtio::SignalableInterrupt;

/// A Doorbell that supports both regular call events and signaling through a VVU device.
#[derive(Clone)]
pub enum Doorbell {
    Call(CallEvent),
    Vfio(DoorbellRegion),
}

impl From<CallEvent> for Doorbell {
    fn from(event: CallEvent) -> Self {
        Doorbell::Call(event)
    }
}

impl SignalableInterrupt for Doorbell {
    fn signal(&self, vector: u16, interrupt_status_mask: u32) {
        match &self {
            Self::Call(evt) => evt.signal(vector, interrupt_status_mask),
            Self::Vfio(evt) => evt.signal(vector, interrupt_status_mask),
        }
    }

    fn signal_config_changed(&self) {
        match &self {
            Self::Call(evt) => evt.signal_config_changed(),
            Self::Vfio(evt) => evt.signal_config_changed(),
        }
    }

    fn get_resample_evt(&self) -> Option<&Event> {
        match &self {
            Self::Call(evt) => evt.get_resample_evt(),
            Self::Vfio(evt) => evt.get_resample_evt(),
        }
    }

    fn do_interrupt_resample(&self) {
        match &self {
            Self::Call(evt) => evt.do_interrupt_resample(),
            Self::Vfio(evt) => evt.do_interrupt_resample(),
        }
    }
}

/// Ops for running vhost-user over virtio (i.e. virtio-vhost-user).
pub struct VvuOps {
    vfio_dev: Arc<VfioDevice>,
    caps: VvuPciCaps,
    notification_evts: Vec<Event>,
}

impl VvuOps {
    pub fn new(device: &mut VvuPciDevice) -> Self {
        Self {
            vfio_dev: Arc::clone(&device.vfio_dev),
            caps: device.caps.clone(),
            notification_evts: std::mem::take(&mut device.notification_evts),
        }
    }
}

impl VhostUserPlatformOps for VvuOps {
    fn protocol(&self) -> Protocol {
        return Protocol::Virtio;
    }

    fn set_mem_table(
        &mut self,
        contexts: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> VhostResult<(GuestMemory, Vec<MappingInfo>)> {
        // virtio-vhost-user doesn't pass FDs.
        if !files.is_empty() {
            return Err(VhostError::InvalidParam);
        }

        let file_offset = self
            .vfio_dev
            .get_offset_for_addr(self.caps.shared_mem_cfg_addr())
            .map_err(|e| {
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

            let cloned_file = self.vfio_dev.dev_file().try_clone().map_err(|e| {
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

    fn set_vring_kick(&mut self, index: u8, file: Option<File>) -> VhostResult<Event> {
        if file.is_some() {
            return Err(VhostError::InvalidParam);
        }
        self.notification_evts[index as usize]
            .try_clone()
            .map_err(|e| {
                error!("failed to clone notification_evts[{}]: {}", index, e);
                VhostError::InvalidOperation
            })
    }

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostResult<Doorbell> {
        if file.is_some() {
            return Err(VhostError::InvalidParam);
        }
        let doorbell = DoorbellRegion::new(index as u8, &self.vfio_dev, &self.caps)?;
        Ok(Doorbell::Vfio(doorbell))
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

impl<O: VhostUserPlatformOps> DeviceRequestHandler<O> {
    /// Attaches to an already bound socket via `listener` and handles incoming messages from the
    /// VMM, which are dispatched to the device backend via the `VhostUserBackend` trait methods.
    pub async fn run_with_listener<L>(self, listener: L, ex: Executor) -> Result<()>
    where
        L::Endpoint: Endpoint<MasterReq> + AsRawDescriptor,
        L: Listener + AsRawDescriptor,
    {
        let mut listener = SlaveListener::<L, _>::new(listener, std::sync::Mutex::new(self))?;
        listener.set_nonblocking(true)?;

        loop {
            // If the listener is not ready on the first call to `accept` and returns `None`, we
            // temporarily convert it into an async I/O source and yield until it signals there is
            // input data awaiting, before trying again.
            match listener
                .accept()
                .context("failed to accept an incoming connection")?
            {
                Some(req_handler) => return run_handler(req_handler, &ex).await,
                None => {
                    // Nobody is on the other end yet, wait until we get a connection.
                    let async_waiter = ex
                        .async_from_local(AsyncWrapper::new(listener))
                        .context("failed to create async waiter")?;
                    async_waiter.wait_readable().await?;

                    // Retrieve the listener back so we can use it again.
                    listener = async_waiter.into_source().into_inner();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::sync::Barrier;

    use tempfile::Builder;
    use tempfile::TempDir;

    use super::*;
    use crate::virtio::vhost::user::device::handler::tests::*;
    use crate::virtio::vhost::user::device::handler::*;
    use crate::virtio::vhost::user::vmm::VhostUserHandler;

    fn temp_dir() -> TempDir {
        Builder::new().prefix("/tmp/vhost_test").tempdir().unwrap()
    }

    #[test]
    fn test_vhost_user_activate() {
        use std::os::unix::net::UnixStream;

        use vmm_vhost::connection::socket::Listener as SocketListener;
        use vmm_vhost::SlaveListener;

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
            let connection = UnixStream::connect(&path).unwrap();
            let mut vmm_handler = VhostUserHandler::new_from_connection(
                connection,
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
        let handler = std::sync::Mutex::new(DeviceRequestHandler::new_with_ops(
            Box::new(FakeBackend::new()),
            VhostUserRegularOps,
        ));
        let mut listener = SlaveListener::<SocketListener, _>::new(listener, handler).unwrap();

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

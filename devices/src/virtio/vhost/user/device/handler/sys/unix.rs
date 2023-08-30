// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use base::error;
use base::info;
use base::AsRawDescriptor;
use base::Event;
use base::MemoryMappingBuilder;
use base::SafeDescriptor;
use cros_async::AsyncWrapper;
use cros_async::Executor;
use vm_memory::GuestMemory;
use vmm_vhost::connection::Endpoint;
use vmm_vhost::message::MasterReq;
use vmm_vhost::message::VhostUserMemoryRegion;
use vmm_vhost::Error as VhostError;
use vmm_vhost::Protocol;
use vmm_vhost::Result as VhostResult;
use vmm_vhost::SlaveReqHandler;
use vmm_vhost::VhostUserSlaveReqHandler;

use crate::vfio::VfioDevice;
use crate::virtio::vhost::user::device::handler::GuestAddress;
use crate::virtio::vhost::user::device::handler::MappingInfo;
use crate::virtio::vhost::user::device::handler::MemoryRegion;
use crate::virtio::vhost::user::device::handler::VhostUserPlatformOps;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciCaps;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;
use crate::virtio::Interrupt;

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
        Protocol::Virtio
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
                vmm_addr: region.user_addr,
                guest_phys: region.guest_phys_addr,
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

    fn set_vring_call(&mut self, index: u8, file: Option<File>) -> VhostResult<Interrupt> {
        if file.is_some() {
            return Err(VhostError::InvalidParam);
        }

        let base = self.caps.doorbell_base_addr();
        let mmap_region = self.vfio_dev.get_region_mmap(base.index);
        let region_offset = self.vfio_dev.get_region_offset(base.index);
        let offset = region_offset + mmap_region[0].offset;

        let mmap = MemoryMappingBuilder::new(mmap_region[0].size as usize)
            .from_file(self.vfio_dev.device_file())
            .offset(offset)
            .build()
            .map_err(|e| {
                error!("Failed to mmap vfio memory region: {}", e);
                VhostError::InvalidOperation
            })?;

        let mmap_offset = base.addr + (index as u64 * self.caps.doorbell_off_multiplier() as u64);
        Ok(Interrupt::new_virtio_vhost_user(
            mmap,
            mmap_offset
                .try_into()
                .expect("mmap_offset too large for usize"),
        ))
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
        let (hdr, files) = match req_handler.recv_header() {
            Ok((hdr, files)) => (hdr, files),
            Err(VhostError::ClientExit) => {
                info!("vhost-user connection closed");
                // Exit as the client closed the connection.
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        };

        if req_handler.needs_wait_for_payload(&hdr) {
            handler_source
                .wait_readable()
                .await
                .context("failed to wait for the handler to become readable")?;
        }
        req_handler.process_message(hdr, files)?;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::sync::Barrier;

    use tempfile::Builder;
    use tempfile::TempDir;

    use vmm_vhost::connection::Listener;

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

        const QUEUES_NUM: usize = 2;

        let dir = temp_dir();
        let mut path = dir.path().to_owned();
        path.push("sock");
        let mut listener = SocketListener::new(&path, true).unwrap();

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
        let handler = std::sync::Mutex::new(DeviceRequestHandler::new(
            Box::new(FakeBackend::new()),
            Box::new(VhostUserRegularOps),
        ));

        // Notify listener is ready.
        tx.send(()).unwrap();

        let endpoint = listener.accept().unwrap().unwrap();
        let mut req_handler = SlaveReqHandler::new(endpoint, handler);

        test_handle_requests(&mut req_handler, QUEUES_NUM);

        dev_bar.wait();

        match req_handler.recv_header() {
            Err(VhostError::ClientExit) => (),
            r => panic!("Err(ClientExit) was expected but {:?}", r),
        }
    }
}

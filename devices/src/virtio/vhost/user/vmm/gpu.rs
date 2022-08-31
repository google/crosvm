// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::thread;

use base::error;
use base::Event;
use base::RawDescriptor;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio::device_constants::gpu;
use crate::virtio::vhost::user::vmm::Connection;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::vhost::user::vmm::VhostUserHandler;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::SharedMemoryMapper;
use crate::virtio::SharedMemoryRegion;
use crate::virtio::VirtioDevice;

pub struct Gpu {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Gpu {
    /// Create a new GPU proxy instance for the VMM.
    ///
    /// `base_features` is the desired set of virtio features.
    /// `socket_path` is the path to the socket of the GPU device.
    /// `pci_bar_size` is the size for the PCI BAR in bytes
    pub fn new(base_features: u64, connection: Connection) -> Result<Gpu> {
        let default_queue_size = gpu::QUEUE_SIZES.len();

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | 1 << gpu::VIRTIO_GPU_F_VIRGL
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_UUID
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_BLOB
            | 1 << gpu::VIRTIO_GPU_F_CONTEXT_INIT
            | 1 << gpu::VIRTIO_GPU_F_RESOURCE_SYNC
            | 1 << gpu::VIRTIO_GPU_F_CREATE_GUEST_HANDLE
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features =
            VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::SLAVE_REQ;

        let handler = VhostUserHandler::new_from_connection(
            connection,
            default_queue_size as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;

        Ok(Gpu {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes: gpu::QUEUE_SIZES[..].to_vec(),
        })
    }
}

impl VirtioDevice for Gpu {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Gpu
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn features(&self) -> u64 {
        self.handler.borrow().avail_features
    }

    fn ack_features(&mut self, features: u64) {
        if let Err(e) = self.handler.borrow_mut().ack_features(features) {
            error!("failed to enable features 0x{:x}: {}", features, e);
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.handler.borrow_mut().read_config(offset, data) {
            error!("failed to read gpu config: {}", e);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if let Err(e) = self.handler.borrow_mut().write_config(offset, data) {
            error!("failed to write gpu config: {}", e);
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        match self
            .handler
            .borrow_mut()
            .activate(mem, interrupt, queues, queue_evts, "gpu")
        {
            Ok((join_handle, kill_evt)) => {
                self.worker_thread = Some(join_handle);
                self.kill_evt = Some(kill_evt);
            }
            Err(e) => {
                error!("failed to activate queues: {}", e);
            }
        }
    }

    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        match self.handler.borrow_mut().get_shared_memory_region() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to get shared memory regions {}", e);
                None
            }
        }
    }

    fn set_shared_memory_mapper(&mut self, mapper: Box<dyn SharedMemoryMapper>) {
        if let Err(e) = self.handler.borrow_mut().set_shared_memory_mapper(mapper) {
            error!("Error setting shared memory mapper {}", e);
        }
    }

    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        true
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset gpu device: {}", e);
            false
        } else {
            true
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            if let Some(worker_thread) = self.worker_thread.take() {
                if let Err(e) = kill_evt.write(1) {
                    error!("failed to write to kill_evt: {}", e);
                    return;
                }
                let _ = worker_thread.join();
            }
        }
    }
}

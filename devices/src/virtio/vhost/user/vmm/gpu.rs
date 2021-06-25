// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cell::RefCell, path::Path, thread};

use base::{error, Event, RawDescriptor, Tube};
use cros_async::Executor;
use vm_memory::GuestMemory;
use vmm_vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::{
    pci::{PciBarConfiguration, PciCapability},
    virtio::{
        gpu::QUEUE_SIZES,
        vhost::user::vmm::{worker::Worker, Result, VhostUserHandler},
        virtio_gpu_config, Interrupt, PciCapabilityType, Queue, VirtioDevice, VirtioPciShmCap,
        GPU_BAR_NUM, GPU_BAR_OFFSET, GPU_BAR_SIZE, TYPE_GPU, VIRTIO_GPU_F_CONTEXT_INIT,
        VIRTIO_GPU_F_CREATE_GUEST_HANDLE, VIRTIO_GPU_F_RESOURCE_BLOB, VIRTIO_GPU_F_RESOURCE_SYNC,
        VIRTIO_GPU_F_RESOURCE_UUID, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_SHM_ID_HOST_VISIBLE,
    },
    PciAddress,
};

pub struct Gpu {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    host_tube: Tube,
    queue_sizes: Vec<u16>,
}

impl Gpu {
    pub fn new<P: AsRef<Path>>(
        base_features: u64,
        socket_path: P,
        host_tube: Tube,
        device_tube: Tube,
    ) -> Result<Gpu> {
        let default_queue_size = QUEUE_SIZES.len();

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | 1 << VIRTIO_GPU_F_VIRGL
            | 1 << VIRTIO_GPU_F_RESOURCE_UUID
            | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
            | 1 << VIRTIO_GPU_F_CONTEXT_INIT
            | 1 << VIRTIO_GPU_F_RESOURCE_SYNC
            | 1 << VIRTIO_GPU_F_CREATE_GUEST_HANDLE
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features =
            VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::SLAVE_REQ;

        let mut handler = VhostUserHandler::new_from_path(
            socket_path,
            default_queue_size as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        handler.set_device_request_channel(device_tube)?;

        Ok(Gpu {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            host_tube,
            queue_sizes: QUEUE_SIZES[..].to_vec(),
        })
    }
}

impl VirtioDevice for Gpu {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_GPU
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
        if let Err(e) = self
            .handler
            .borrow_mut()
            .read_config::<virtio_gpu_config>(offset, data)
        {
            error!("failed to read gpu config: {}", e);
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        if let Err(e) = self
            .handler
            .borrow_mut()
            .write_config::<virtio_gpu_config>(offset, data)
        {
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
        if let Err(e) = self
            .handler
            .borrow_mut()
            .activate(&mem, &interrupt, &queues, &queue_evts)
        {
            error!("failed to activate queues: {}", e);
            return;
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed creating kill Event pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let worker_result = thread::Builder::new()
            .name("vhost_user_gpu".to_string())
            .spawn(move || {
                let ex = Executor::new().expect("failed to create an executor");
                let mut worker = Worker {
                    queues,
                    mem,
                    kill_evt,
                };

                if let Err(e) = worker.run(&ex, interrupt) {
                    error!("failed to start a worker: {}", e);
                }
                worker
            });

        match worker_result {
            Err(e) => {
                error!("failed to spawn vhost_user_gpu worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn get_device_bars(&mut self, address: PciAddress) -> Vec<PciBarConfiguration> {
        if let Err(e) = self.host_tube.send(&address) {
            error!("failed to send `PciAddress` to gpu device: {}", e);
            return Vec::new();
        }

        match self.host_tube.recv() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!(
                    "failed to receive `PciBarConfiguration` from gpu device: {}",
                    e
                );
                Vec::new()
            }
        }
    }

    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![Box::new(VirtioPciShmCap::new(
            PciCapabilityType::SharedMemoryConfig,
            GPU_BAR_NUM,
            GPU_BAR_OFFSET,
            GPU_BAR_SIZE,
            VIRTIO_GPU_SHM_ID_HOST_VISIBLE,
        ))]
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

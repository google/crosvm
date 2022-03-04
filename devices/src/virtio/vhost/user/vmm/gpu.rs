// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cell::RefCell, path::Path, thread};

use base::{error, Event, RawDescriptor, Tube};
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

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

/// Current state of our Gpu.
enum GpuState {
    /// Created, address has not yet been assigned through `get_device_bars`.
    Init {
        /// VMM-side Tube to the GPU process from which we will send the PCI address, retrieve the
        /// BAR configuration, and send the vhost-user control tube in `get_device_bars`.
        host_gpu_tube: Tube,
        /// Device-side control tube to be sent during `get_device_bars`.
        device_control_tube: Tube,
    },
    /// Address has been set through `get_device_bars`.
    Configured,
}

pub struct Gpu {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    state: GpuState,
    queue_sizes: Vec<u16>,
}

impl Gpu {
    /// Create a new GPU proxy instance for the VMM.
    ///
    /// `base_features` is the desired set of virtio features.
    /// `socket_path` is the path to the socket of the GPU device.
    /// `gpu_tubes` is a pair of (vmm side, device side) connected tubes that are used to perform
    /// the initial configuration of the GPU device.
    /// `device_control_tube` is the device-side tube to be passed to the GPU device so it can
    /// perform `VmRequest`s.
    pub fn new<P: AsRef<Path>>(
        base_features: u64,
        socket_path: P,
        gpu_tubes: (Tube, Tube),
        device_control_tube: Tube,
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
        handler.set_device_request_channel(gpu_tubes.1)?;

        Ok(Gpu {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            state: GpuState::Init {
                host_gpu_tube: gpu_tubes.0,
                device_control_tube,
            },
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
                let mut worker = Worker {
                    queues,
                    mem,
                    kill_evt,
                };

                if let Err(e) = worker.run(interrupt) {
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
        let (host_gpu_tube, device_control_tube) =
            match std::mem::replace(&mut self.state, GpuState::Configured) {
                GpuState::Init {
                    host_gpu_tube,
                    device_control_tube,
                } => (host_gpu_tube, device_control_tube),
                GpuState::Configured => {
                    panic!("get_device_bars shall not be called more than once!")
                }
            };

        if let Err(e) = host_gpu_tube.send(&address) {
            error!("failed to send `PciAddress` to gpu device: {}", e);
            return Vec::new();
        }

        let res = match host_gpu_tube.recv() {
            Ok(cfg) => cfg,
            Err(e) => {
                error!(
                    "failed to receive `PciBarConfiguration` from gpu device: {}",
                    e
                );
                return Vec::new();
            }
        };

        if let Err(e) = host_gpu_tube.send(&device_control_tube) {
            error!("failed to send device control tube to gpu device: {}", e);
            return Vec::new();
        }

        res
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

// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{cell::RefCell, os::unix::net::UnixStream, path::Path, thread};

use base::{error, Event, RawDescriptor};
use data_model::Le64;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::{
    vhost::{
        user::vmm::{handler::VhostUserHandler, worker::Worker, Error, Result},
        vsock,
    },
    Interrupt, Queue, VirtioDevice, TYPE_VSOCK, VIRTIO_F_VERSION_1,
};

pub struct Vsock {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Vsock {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Vsock> {
        let socket = UnixStream::connect(socket_path).map_err(Error::SocketConnect)?;

        let init_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_features = init_features
            | base_features
            | 1 << VIRTIO_F_VERSION_1
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_INDIRECT_DESC
            | 1 << virtio_sys::vhost::VIRTIO_RING_F_EVENT_IDX
            | 1 << virtio_sys::vhost::VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << virtio_sys::vhost::VHOST_F_LOG_ALL
            | 1 << virtio_sys::vhost::VIRTIO_F_ANY_LAYOUT;
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            vsock::QUEUE_SIZES.len() as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(vsock::QUEUE_SIZE, vsock::QUEUE_SIZES.len())?;

        Ok(Vsock {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl Drop for Vsock {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Vsock {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn features(&self) -> u64 {
        self.handler.borrow().avail_features
    }

    fn ack_features(&mut self, features: u64) {
        if let Err(e) = self.handler.borrow_mut().ack_features(features) {
            error!("failed to enable features 0x{:x}: {}", features, e);
        }
    }

    fn device_type(&self) -> u32 {
        TYPE_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_sizes.as_slice()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.handler.borrow_mut().read_config::<Le64>(offset, data) {
            error!("failed to read config: {}", e);
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
            .name("vhost_user_vsock".to_string())
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
                error!("failed to spawn virtio_vsock worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset vsock device: {}", e);
            false
        } else {
            true
        }
    }
}

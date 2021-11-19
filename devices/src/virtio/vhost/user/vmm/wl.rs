// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::path::Path;
use std::thread;

use base::{error, Event, RawDescriptor};
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::vhost::user::vmm::{worker::Worker, Result, VhostUserHandler};
use crate::virtio::wl::{
    QUEUE_SIZE, QUEUE_SIZES, VIRTIO_WL_F_SEND_FENCES, VIRTIO_WL_F_TRANS_FLAGS,
};
use crate::virtio::{Interrupt, Queue, VirtioDevice, TYPE_WL};

pub struct Wl {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Wl {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Wl> {
        let default_queue_size = QUEUE_SIZES.len();

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | 1 << VIRTIO_WL_F_TRANS_FLAGS
            | 1 << VIRTIO_WL_F_SEND_FENCES
            | base_features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_path(
            socket_path,
            default_queue_size as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, default_queue_size)?;

        Ok(Wl {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl VirtioDevice for Wl {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_WL
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

    fn read_config(&self, _offset: u64, _data: &mut [u8]) {}

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
            .name("vhost_user_wl".to_string())
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
                error!("failed to spawn vhost_user_wl worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset wl device: {}", e);
            false
        } else {
            true
        }
    }
}

impl Drop for Wl {
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

// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;

use base::{error, Event, RawDescriptor};
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::console::{virtio_console_config, QUEUE_SIZE};
use crate::virtio::vhost::user::vmm::{handler::VhostUserHandler, worker::Worker, Error, Result};
use crate::virtio::{Interrupt, Queue, VirtioDevice, TYPE_CONSOLE};

pub struct Console {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Console {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Console> {
        let socket = UnixStream::connect(&socket_path).map_err(Error::SocketConnect)?;

        // VIRTIO_CONSOLE_F_MULTIPORT is not supported, so we just implement port 0 (receiveq,
        // transmitq)
        let queues_num = 2;

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | base_features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            queues_num,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, queues_num as usize)?;

        Ok(Console {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl VirtioDevice for Console {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn features(&self) -> u64 {
        self.handler.borrow().avail_features
    }

    fn device_type(&self) -> u32 {
        TYPE_CONSOLE
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_sizes.as_slice()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Err(e) = self
            .handler
            .borrow_mut()
            .read_config::<virtio_console_config>(offset, data)
        {
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
            .name("vhost_user_virtio_console".to_string())
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
                error!("failed to spawn vhost-user virtio_console worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset console device: {}", e);
            false
        } else {
            true
        }
    }
}

impl Drop for Console {
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

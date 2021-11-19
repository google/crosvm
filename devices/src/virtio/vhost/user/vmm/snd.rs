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

use crate::virtio::snd::layout::virtio_snd_config;
use crate::virtio::vhost::user::vmm::{handler::VhostUserHandler, worker::Worker, Error, Result};
use crate::virtio::TYPE_SOUND;
use crate::virtio::{Interrupt, Queue, VirtioDevice};

// A vhost-user snd device.
pub struct Snd {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

const QUEUE_SIZE: u16 = 1024;

// control, event, tx, and rx queues
const NUM_QUEUES: usize = 4;

impl Snd {
    // Create a vhost-user snd device.
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Snd> {
        let socket = UnixStream::connect(&socket_path).map_err(Error::SocketConnect)?;

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            NUM_QUEUES as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, NUM_QUEUES)?;

        Ok(Snd {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl VirtioDevice for Snd {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> u32 {
        TYPE_SOUND
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
            .read_config::<virtio_snd_config>(offset, data)
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

        let (self_kill_evt, kill_evt) =
            match Event::new().and_then(|evt| Ok((evt.try_clone()?, evt))) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed creating kill Event pair: {}", e);
                    return;
                }
            };
        self.kill_evt = Some(self_kill_evt);

        let worker_result = thread::Builder::new()
            .name("vhost_user_virtio_snd".to_string())
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
                error!("failed to spawn vhost-user virtio_snd worker: {}", e);
            }
            Ok(join_handle) => {
                self.worker_thread = Some(join_handle);
            }
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset snd device: {}", e);
            false
        } else {
            true
        }
    }
}

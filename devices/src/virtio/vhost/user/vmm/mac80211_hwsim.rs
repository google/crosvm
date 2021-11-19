// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::u32;

use base::{error, Event, RawDescriptor};
use remain::sorted;
use thiserror::Error as ThisError;
use vm_memory::GuestMemory;
use vmm_vhost::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use crate::virtio::vhost::user::vmm::{handler::VhostUserHandler, worker::Worker, Error};
use crate::virtio::{Interrupt, Queue, VirtioDevice, TYPE_MAC80211_HWSIM, VIRTIO_F_VERSION_1};

use std::result::Result;

#[sorted]
#[derive(ThisError, Debug)]
enum Mac80211HwsimError {
    #[error("failed to activate queues: {0}")]
    ActivateQueue(Error),
    #[error("failed to kill event pair: {0}")]
    CreateKillEventPair(base::Error),
    #[error("failed to spawn mac80211_hwsim worker: {0}")]
    SpawnWorker(std::io::Error),
}

const QUEUE_SIZE: u16 = 256;
const QUEUE_COUNT: usize = 2;

pub struct Mac80211Hwsim {
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<Worker>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Mac80211Hwsim {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P) -> Result<Mac80211Hwsim, Error> {
        let socket = UnixStream::connect(&socket_path).map_err(Error::SocketConnect)?;

        let allow_features = 1 << VIRTIO_F_VERSION_1
            | base_features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features = VhostUserProtocolFeatures::empty();

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            QUEUE_COUNT as u64, /* # of queues */
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, QUEUE_COUNT)?;

        Ok(Mac80211Hwsim {
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }

    fn activate_internal(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) -> Result<(), Mac80211HwsimError> {
        self.handler
            .borrow_mut()
            .activate(&mem, &interrupt, &queues, &queue_evts)
            .map_err(Mac80211HwsimError::ActivateQueue)?;

        let (self_kill_evt, kill_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .map_err(Mac80211HwsimError::CreateKillEventPair)?;

        self.kill_evt = Some(self_kill_evt);

        let join_handle = thread::Builder::new()
            .name("vhost_user_mac80211_hwsim".to_string())
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
            })
            .map_err(Mac80211HwsimError::SpawnWorker)?;

        self.worker_thread = Some(join_handle);

        Ok(())
    }
}

impl Drop for Mac80211Hwsim {
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

impl VirtioDevice for Mac80211Hwsim {
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
        TYPE_MAC80211_HWSIM
    }

    fn queue_max_sizes(&self) -> &[u16] {
        self.queue_sizes.as_slice()
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    ) {
        if let Err(e) = self.activate_internal(mem, interrupt, queues, queue_evts) {
            error!("Failed to activate mac80211_hwsim: {}", e);
        }
    }

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset mac80211_hwsim device: {}", e);
            false
        } else {
            true
        }
    }
}

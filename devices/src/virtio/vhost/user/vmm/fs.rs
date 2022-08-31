// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;

use base::error;
use base::Event;
use base::RawDescriptor;
use data_model::DataInit;
use data_model::Le32;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;
use vmm_vhost::Error as VhostUserError;

use crate::virtio::copy_config;
use crate::virtio::fs::virtio_fs_config;
use crate::virtio::fs::FS_MAX_TAG_LEN;
use crate::virtio::fs::QUEUE_SIZE;
use crate::virtio::vhost::user::vmm::handler::VhostUserHandler;
use crate::virtio::vhost::user::vmm::Error;
use crate::virtio::vhost::user::vmm::Result;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

pub struct Fs {
    cfg: virtio_fs_config,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}
impl Fs {
    pub fn new<P: AsRef<Path>>(base_features: u64, socket_path: P, tag: &str) -> Result<Fs> {
        if tag.len() > FS_MAX_TAG_LEN {
            return Err(Error::TagTooLong {
                len: tag.len(),
                max: FS_MAX_TAG_LEN,
            });
        }

        // The spec requires a minimum of 2 queues: one worker queue and one high priority queue
        let default_queue_size = 2;

        let mut cfg_tag = [0u8; FS_MAX_TAG_LEN];
        cfg_tag[..tag.len()].copy_from_slice(tag.as_bytes());

        let cfg = virtio_fs_config {
            tag: cfg_tag,
            // Only count the worker queues, exclude the high prio queue
            num_request_queues: Le32::from(default_queue_size - 1),
        };

        let socket = UnixStream::connect(&socket_path).map_err(Error::SocketConnect)?;

        let allow_features = 1u64 << crate::virtio::VIRTIO_F_VERSION_1
            | base_features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features =
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG;

        let mut handler = VhostUserHandler::new_from_stream(
            socket,
            default_queue_size as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;
        let queue_sizes = handler.queue_sizes(QUEUE_SIZE, default_queue_size as usize)?;

        Ok(Fs {
            cfg,
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes,
        })
    }
}

impl VirtioDevice for Fs {
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Fs
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
        match self.handler.borrow_mut().read_config(offset, data) {
            Ok(()) => {}
            // copy local config when VhostUserProtocolFeatures::CONFIG is not supported by the
            // device
            Err(Error::GetConfig(VhostUserError::InvalidOperation)) => {
                copy_config(data, 0, self.cfg.as_slice(), offset)
            }
            Err(e) => error!("Failed to fetch device config: {}", e),
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
            .activate(mem, interrupt, queues, queue_evts, "fs")
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

    fn reset(&mut self) -> bool {
        if let Err(e) = self.handler.borrow_mut().reset(self.queue_sizes.len()) {
            error!("Failed to reset fs device: {}", e);
            false
        } else {
            true
        }
    }
}

impl Drop for Fs {
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

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::path::Path;
use std::thread;

use anyhow::Result;
use base::error;
use base::Event;
use base::RawDescriptor;
use vm_memory::GuestMemory;
use vmm_vhost::message::VhostUserProtocolFeatures;
use vmm_vhost::message::VhostUserVirtioFeatures;

use crate::virtio::device_constants::video::all_backend_virtio_features;
use crate::virtio::device_constants::video::VideoDeviceType;
use crate::virtio::device_constants::video::QUEUE_SIZES;
use crate::virtio::vhost::user::vmm::VhostUserHandler;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;
use crate::virtio::VirtioDevice;

pub struct Video {
    device_type: VideoDeviceType,
    kill_evt: Option<Event>,
    worker_thread: Option<thread::JoinHandle<()>>,
    handler: RefCell<VhostUserHandler>,
    queue_sizes: Vec<u16>,
}

impl Video {
    pub fn new<P: AsRef<Path>>(
        base_features: u64,
        socket_path: P,
        device_type: VideoDeviceType,
    ) -> Result<Video> {
        let allow_features = base_features
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
            | all_backend_virtio_features();

        let init_features = base_features | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let allow_protocol_features = VhostUserProtocolFeatures::CONFIG;

        let handler = VhostUserHandler::new_from_path(
            socket_path,
            QUEUE_SIZES.len() as u64,
            allow_features,
            init_features,
            allow_protocol_features,
        )?;

        Ok(Video {
            device_type,
            kill_evt: None,
            worker_thread: None,
            handler: RefCell::new(handler),
            queue_sizes: QUEUE_SIZES[..].to_vec(),
        })
    }
}

impl VirtioDevice for Video {
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

    fn device_type(&self) -> DeviceType {
        match self.device_type {
            VideoDeviceType::Decoder => DeviceType::VideoDec,
            VideoDeviceType::Encoder => DeviceType::VideoEnc,
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_sizes
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Err(e) = self.handler.borrow_mut().read_config(offset, data) {
            error!("failed to read video config: {}", e);
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
            .activate(mem, interrupt, queues, queue_evts, "video")
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
            error!("Failed to reset video device: {}", e);
            false
        } else {
            true
        }
    }
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the virtio video encoder and decoder devices.
//! The current implementation uses [v3 RFC] of the virtio-video protocol.
//!
//! [v3 RFC]: https://markmail.org/thread/wxdne5re7aaugbjg

use std::fmt::{self, Display};
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread;

use base::{error, Error as SysError, EventFd};
use data_model::{DataInit, Le32};
use vm_memory::GuestMemory;

use crate::virtio::resource_bridge::ResourceRequestSocket;
use crate::virtio::virtio_device::VirtioDevice;
use crate::virtio::{self, copy_config, DescriptorError, Interrupt, VIRTIO_F_VERSION_1};

#[macro_use]
mod macros;
mod async_cmd_desc_map;
mod command;
mod control;
mod decoder;
mod device;
mod encoder;
mod error;
mod event;
mod format;
mod params;
mod protocol;
mod response;
mod worker;

use command::ReadCmdError;
use device::AsyncCmdTag;
use worker::Worker;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

/// An error indicating something went wrong in virtio-video's worker.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a libvda instance.
    LibvdaCreationFailed(libvda::Error),
    /// Creating PollContext failed.
    PollContextCreationFailed(SysError),
    /// A DescriptorChain contains invalid data.
    InvalidDescriptorChain(DescriptorError),
    /// No available descriptor in which an event is written to.
    DescriptorNotAvailable,
    /// Error while polling for events.
    PollError(SysError),
    /// Failed to read a virtio-video command.
    ReadFailure(ReadCmdError),
    /// Got response for an unexpected asynchronous command.
    UnexpectedResponse(AsyncCmdTag),
    /// Failed to write an event into the event queue.
    WriteEventFailure {
        event: event::VideoEvt,
        error: std::io::Error,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            LibvdaCreationFailed(e) => write!(f, "failed to create a libvda instance: {}", e),
            PollContextCreationFailed(e) => write!(f, "failed to create PollContext: {}", e),
            InvalidDescriptorChain(e) => write!(f, "DescriptorChain contains invalid data: {}", e),
            DescriptorNotAvailable => {
                write!(f, "no available descriptor in which an event is written to")
            }
            PollError(err) => write!(f, "failed to poll events: {}", err),
            ReadFailure(e) => write!(f, "failed to read a command from the guest: {}", e),
            UnexpectedResponse(tag) => {
                write!(f, "got a response for an untracked command: {:?}", tag)
            }
            WriteEventFailure { event, error } => write!(
                f,
                "failed to write an event {:?} into event queue: {}",
                event, error
            ),
        }
    }
}

impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum VideoDeviceType {
    Decoder,
    Encoder,
}

pub struct VideoDevice {
    device_type: VideoDeviceType,
    kill_evt: Option<EventFd>,
    resource_bridge: Option<ResourceRequestSocket>,
}

impl VideoDevice {
    pub fn new(
        device_type: VideoDeviceType,
        resource_bridge: Option<ResourceRequestSocket>,
    ) -> VideoDevice {
        VideoDevice {
            device_type,
            kill_evt: None,
            resource_bridge,
        }
    }
}

impl Drop for VideoDevice {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }
    }
}

impl VirtioDevice for VideoDevice {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();
        if let Some(resource_bridge) = &self.resource_bridge {
            keep_fds.push(resource_bridge.as_raw_fd());
        }
        keep_fds
    }

    fn device_type(&self) -> u32 {
        match &self.device_type {
            VideoDeviceType::Decoder => virtio::TYPE_VIDEO_DEC,
            VideoDeviceType::Encoder => virtio::TYPE_VIDEO_ENC,
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        1u64 << VIRTIO_F_VERSION_1
            | 1u64 << protocol::VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG
            | 1u64 << protocol::VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut cfg = protocol::virtio_video_config {
            version: Le32::from(0),
            max_caps_length: Le32::from(1024), // Set a big number
            max_resp_length: Le32::from(1024), // Set a big number
        };
        copy_config(data, 0, cfg.as_mut_slice(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<virtio::queue::Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != QUEUE_SIZES.len() {
            error!(
                "wrong number of queues are passed: expected {}, actual {}",
                queues.len(),
                QUEUE_SIZES.len()
            );
            return;
        }
        if queue_evts.len() != QUEUE_SIZES.len() {
            error!(
                "wrong number of event FDs are passed: expected {}, actual {}",
                queue_evts.len(),
                QUEUE_SIZES.len()
            );
        }

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill EventFd pair: {:?}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let cmd_queue = queues.remove(0);
        let cmd_evt = queue_evts.remove(0);
        let event_queue = queues.remove(0);
        let event_evt = queue_evts.remove(0);
        let resource_bridge = match self.resource_bridge.take() {
            Some(r) => r,
            None => {
                error!("no resource bridge is passed");
                return;
            }
        };
        let mut worker = Worker {
            interrupt,
            mem,
            cmd_evt,
            event_evt,
            kill_evt,
            resource_bridge,
        };
        let worker_result = match &self.device_type {
            VideoDeviceType::Decoder => thread::Builder::new()
                .name("virtio video decoder".to_owned())
                .spawn(move || {
                    let vda = libvda::decode::VdaInstance::new(libvda::decode::VdaImplType::Gavda)
                        .map_err(Error::LibvdaCreationFailed)?;
                    let device = decoder::Decoder::new(&vda);
                    worker.run(cmd_queue, event_queue, device)
                }),
            VideoDeviceType::Encoder => thread::Builder::new()
                .name("virtio video encoder".to_owned())
                .spawn(move || {
                    let device = encoder::Encoder::new();
                    worker.run(cmd_queue, event_queue, device)
                }),
        };
        if let Err(e) = worker_result {
            error!(
                "failed to spawn virtio_video worker for {:?}: {}",
                &self.device_type, e
            );
            return;
        }
    }
}

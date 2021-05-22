// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the virtio video encoder and decoder devices.
//! The current implementation uses [v3 RFC] of the virtio-video protocol.
//!
//! [v3 RFC]: https://markmail.org/thread/wxdne5re7aaugbjg

use std::fmt::{self, Display};
use std::thread;

use base::{error, info, AsRawDescriptor, Error as SysError, Event, RawDescriptor, Tube};
use data_model::{DataInit, Le32};
use vm_memory::GuestMemory;

use crate::virtio::virtio_device::VirtioDevice;
use crate::virtio::{self, copy_config, DescriptorError, Interrupt};

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

mod vda;

use command::ReadCmdError;
use worker::Worker;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

/// An error indicating something went wrong in virtio-video's worker.
#[derive(Debug)]
pub enum Error {
    /// Creating WaitContext failed.
    WaitContextCreationFailed(SysError),
    /// A DescriptorChain contains invalid data.
    InvalidDescriptorChain(DescriptorError),
    /// No available descriptor in which an event is written to.
    DescriptorNotAvailable,
    /// Error while polling for events.
    WaitError(SysError),
    /// Failed to read a virtio-video command.
    ReadFailure(ReadCmdError),
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
            WaitContextCreationFailed(e) => write!(f, "failed to create WaitContext: {}", e),
            InvalidDescriptorChain(e) => write!(f, "DescriptorChain contains invalid data: {}", e),
            DescriptorNotAvailable => {
                write!(f, "no available descriptor in which an event is written to")
            }
            WaitError(err) => write!(f, "failed to wait for events: {}", err),
            ReadFailure(e) => write!(f, "failed to read a command from the guest: {}", e),
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
    kill_evt: Option<Event>,
    resource_bridge: Option<Tube>,
    base_features: u64,
}

impl VideoDevice {
    pub fn new(
        base_features: u64,
        device_type: VideoDeviceType,
        resource_bridge: Option<Tube>,
    ) -> VideoDevice {
        VideoDevice {
            device_type,
            kill_evt: None,
            resource_bridge,
            base_features,
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
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = Vec::new();
        if let Some(resource_bridge) = &self.resource_bridge {
            keep_rds.push(resource_bridge.as_raw_descriptor());
        }
        keep_rds
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
        self.base_features
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
        mut queue_evts: Vec<Event>,
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
                "wrong number of events are passed: expected {}, actual {}",
                queue_evts.len(),
                QUEUE_SIZES.len()
            );
        }

        let (self_kill_evt, kill_evt) = match Event::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("failed to create kill Event pair: {:?}", e);
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
        let mut worker = Worker::new(
            interrupt,
            mem,
            cmd_queue,
            cmd_evt,
            event_queue,
            event_evt,
            kill_evt,
        );
        let worker_result = match &self.device_type {
            VideoDeviceType::Decoder => thread::Builder::new()
                .name("virtio video decoder".to_owned())
                .spawn(move || {
                    let device = match decoder::Decoder::new(resource_bridge) {
                        Ok(device) => Box::new(device),
                        Err(e) => {
                            error!("Failed to initialize vda: {}", e);
                            return;
                        }
                    };
                    if let Err(e) = worker.run(device) {
                        error!("Failed to start decoder worker: {}", e);
                    };
                    // Don't return any information since the return value is never checked.
                }),
            VideoDeviceType::Encoder => thread::Builder::new()
                .name("virtio video encoder".to_owned())
                .spawn(move || {
                    let device = match encoder::EncoderDevice::new(resource_bridge) {
                        Ok(d) => Box::new(d),
                        Err(e) => {
                            error!("Failed to create encoder device: {}", e);
                            return;
                        }
                    };
                    if let Err(e) = worker.run(device) {
                        error!("Failed to start encoder worker: {}", e);
                    }
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

/// Manages the zero-length, EOS-marked buffer signaling the end of a stream.
///
/// Both the decoder and encoder need to signal end-of-stream events using a zero-sized buffer
/// marked with the `VIRTIO_VIDEO_BUFFER_FLAG_EOS` flag. This struct allows to keep a buffer aside
/// for that purpose.
///
/// TODO(b/149725148): Remove this when libvda supports buffer flags.
struct EosBufferManager {
    stream_id: u32,
    eos_buffer: Option<u32>,
    client_awaits_eos: bool,
    responses: Vec<device::VideoEvtResponseType>,
}

impl EosBufferManager {
    /// Create a new EOS manager for stream `stream_id`.
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            eos_buffer: None,
            client_awaits_eos: false,
            responses: Default::default(),
        }
    }

    /// Attempt to reserve buffer `buffer_id` for use as EOS buffer.
    ///
    /// This method should be called by the output buffer queueing code of the device. It returns
    /// `true` if the buffer has been kept aside for EOS, `false` otherwise (which means another
    /// buffer is already kept aside for EOS). If `true` is returned, the client must not use the
    /// buffer for any other purpose.
    fn try_reserve_eos_buffer(&mut self, buffer_id: u32) -> bool {
        let is_none = self.eos_buffer.is_none();

        if is_none {
            info!(
                "stream {}: keeping buffer {} aside to signal EOS.",
                self.stream_id, buffer_id
            );
            self.eos_buffer = Some(buffer_id);
        }

        is_none
    }

    /// Attempt to complete an EOS event using the previously reserved buffer, if available.
    ///
    /// `responses` is a vector of responses to be sent to the driver along with the EOS buffer. If
    /// an EOS buffer has been made available using the `try_reserve_eos_buffer` method, then this
    /// method returns the `responses` vector with the EOS buffer dequeue appended in first
    /// position.
    ///
    /// If no EOS buffer is available, then the contents of `responses` is put aside, and will be
    /// returned the next time this method is called with an EOS buffer available. When this
    /// happens, `client_awaits_eos` will be set to true, and the client can check this member and
    /// call this method again right after queuing the next buffer to obtain the EOS response as
    /// soon as is possible.
    fn try_complete_eos(
        &mut self,
        responses: Vec<device::VideoEvtResponseType>,
    ) -> Option<Vec<device::VideoEvtResponseType>> {
        let eos_buffer_id = self.eos_buffer.take().or_else(|| {
            info!("stream {}: no EOS resource available on successful flush response, waiting for next buffer to be queued.", self.stream_id);
            self.client_awaits_eos = true;
            if !self.responses.is_empty() {
                error!("stream {}: EOS requested while one is already in progress. This is a bug!", self.stream_id);
            }
            self.responses = responses;
            None
        })?;

        let eos_tag = device::AsyncCmdTag::Queue {
            stream_id: self.stream_id,
            queue_type: command::QueueType::Output,
            resource_id: eos_buffer_id,
        };

        let eos_response = response::CmdResponse::ResourceQueue {
            timestamp: 0,
            flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_EOS,
            size: 0,
        };

        self.client_awaits_eos = false;

        info!(
            "stream {}: signaling EOS using buffer {}.",
            self.stream_id, eos_buffer_id
        );

        let mut responses = std::mem::take(&mut self.responses);
        responses.insert(
            0,
            device::VideoEvtResponseType::AsyncCmd(device::AsyncCmdResponse::from_response(
                eos_tag,
                eos_response,
            )),
        );

        Some(responses)
    }

    /// Reset the state of the manager, for use during e.g. stream resets.
    fn reset(&mut self) {
        self.eos_buffer = None;
        self.client_awaits_eos = false;
        self.responses.clear();
    }
}

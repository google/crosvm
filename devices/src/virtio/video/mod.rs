// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the virtio video encoder and decoder devices.
//! The current implementation uses [v3 RFC] of the virtio-video protocol.
//!
//! [v3 RFC]: https://markmail.org/thread/wxdne5re7aaugbjg

use std::thread;

#[cfg(feature = "video-encoder")]
use base::info;
use base::{error, AsRawDescriptor, Error as SysError, Event, RawDescriptor, Tube};
use data_model::{DataInit, Le32};
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;

use crate::virtio::virtio_device::VirtioDevice;
use crate::virtio::{self, copy_config, DescriptorError, Interrupt};

#[macro_use]
mod macros;
mod async_cmd_desc_map;
mod command;
mod control;
#[cfg(feature = "video-decoder")]
mod decoder;
mod device;
#[cfg(feature = "video-encoder")]
mod encoder;
mod error;
mod event;
mod format;
mod params;
mod protocol;
mod resource;
mod response;
mod worker;

#[cfg(all(feature = "video-decoder", not(feature = "libvda")))]
compile_error!("The \"video-decoder\" feature requires \"libvda\" to also be enabled.");

#[cfg(all(feature = "video-encoder", not(feature = "libvda")))]
compile_error!("The \"video-encoder\" feature requires \"libvda\" to also be enabled.");

#[cfg(feature = "libvda")]
mod vda;

use command::ReadCmdError;
use device::Device;
use worker::Worker;

const QUEUE_SIZE: u16 = 256;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

/// An error indicating something went wrong in virtio-video's worker.
#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// No available descriptor in which an event is written to.
    #[error("no available descriptor in which an event is written to")]
    DescriptorNotAvailable,
    /// A DescriptorChain contains invalid data.
    #[error("DescriptorChain contains invalid data: {0}")]
    InvalidDescriptorChain(DescriptorError),
    /// Failed to read a virtio-video command.
    #[error("failed to read a command from the guest: {0}")]
    ReadFailure(ReadCmdError),
    /// Creating WaitContext failed.
    #[error("failed to create WaitContext: {0}")]
    WaitContextCreationFailed(SysError),
    /// Error while polling for events.
    #[error("failed to wait for events: {0}")]
    WaitError(SysError),
    /// Failed to write an event into the event queue.
    #[error("failed to write an event {event:?} into event queue: {error}")]
    WriteEventFailure {
        event: event::VideoEvt,
        error: std::io::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum VideoDeviceType {
    #[cfg(feature = "video-decoder")]
    Decoder,
    #[cfg(feature = "video-encoder")]
    Encoder,
}

pub struct VideoDevice {
    device_type: VideoDeviceType,
    backend: VideoBackendType,
    kill_evt: Option<Event>,
    resource_bridge: Option<Tube>,
    base_features: u64,
}

impl VideoDevice {
    pub fn new(
        base_features: u64,
        device_type: VideoDeviceType,
        backend: VideoBackendType,
        resource_bridge: Option<Tube>,
    ) -> VideoDevice {
        VideoDevice {
            device_type,
            backend,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VideoBackendType {
    #[cfg(feature = "libvda")]
    Libvda,
    #[cfg(feature = "libvda")]
    LibvdaVd,
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
            #[cfg(feature = "video-decoder")]
            VideoDeviceType::Decoder => virtio::TYPE_VIDEO_DEC,
            #[cfg(feature = "video-encoder")]
            VideoDeviceType::Encoder => virtio::TYPE_VIDEO_ENC,
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        // We specify the type to avoid an extra compilation error in case no backend is enabled
        // and this match statement becomes empty.
        let backend_features: u64 = match self.backend {
            #[cfg(feature = "libvda")]
            VideoBackendType::Libvda | VideoBackendType::LibvdaVd => {
                vda::supported_virtio_features()
            }
        };

        self.base_features | backend_features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut device_name = [0u8; 32];
        match self.backend {
            #[cfg(feature = "libvda")]
            VideoBackendType::Libvda => {
                (&mut device_name[0..6]).copy_from_slice("libvda".as_bytes())
            }
            #[cfg(feature = "libvda")]
            VideoBackendType::LibvdaVd => {
                (&mut device_name[0..8]).copy_from_slice("libvdavd".as_bytes())
            }
        };
        let mut cfg = protocol::virtio_video_config {
            version: Le32::from(0),
            max_caps_length: Le32::from(1024), // Set a big number
            max_resp_length: Le32::from(1024), // Set a big number
            device_name,
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
        let backend = self.backend;
        let resource_bridge = match self.resource_bridge.take() {
            Some(r) => r,
            None => {
                error!("no resource bridge is passed");
                return;
            }
        };
        let mut worker = Worker::new(
            interrupt,
            mem.clone(),
            cmd_queue,
            cmd_evt,
            event_queue,
            event_evt,
            kill_evt,
        );
        let worker_result = match &self.device_type {
            #[cfg(feature = "video-decoder")]
            VideoDeviceType::Decoder => thread::Builder::new()
                .name("virtio video decoder".to_owned())
                .spawn(move || {
                    let device: Box<dyn Device> = match backend {
                        #[cfg(feature = "libvda")]
                        VideoBackendType::Libvda => {
                            let vda = match decoder::backend::vda::LibvdaDecoder::new(
                                libvda::decode::VdaImplType::Gavda,
                            ) {
                                Ok(vda) => vda,
                                Err(e) => {
                                    error!("Failed to initialize VDA for decoder: {}", e);
                                    return;
                                }
                            };
                            Box::new(decoder::Decoder::new(vda, resource_bridge, mem))
                        }
                        #[cfg(feature = "libvda")]
                        VideoBackendType::LibvdaVd => {
                            let vda = match decoder::backend::vda::LibvdaDecoder::new(
                                libvda::decode::VdaImplType::Gavd,
                            ) {
                                Ok(vda) => vda,
                                Err(e) => {
                                    error!("Failed to initialize VD for decoder: {}", e);
                                    return;
                                }
                            };
                            Box::new(decoder::Decoder::new(vda, resource_bridge, mem))
                        }
                    };

                    if let Err(e) = worker.run(device) {
                        error!("Failed to start decoder worker: {}", e);
                    };
                    // Don't return any information since the return value is never checked.
                }),
            #[cfg(feature = "video-encoder")]
            VideoDeviceType::Encoder => thread::Builder::new()
                .name("virtio video encoder".to_owned())
                .spawn(move || {
                    let device: Box<dyn Device> = match backend {
                        #[cfg(feature = "libvda")]
                        VideoBackendType::Libvda => {
                            let vda = match encoder::backend::vda::LibvdaEncoder::new() {
                                Ok(vda) => vda,
                                Err(e) => {
                                    error!("Failed to initialize VDA for encoder: {}", e);
                                    return;
                                }
                            };

                            match encoder::EncoderDevice::new(vda, resource_bridge, mem) {
                                Ok(encoder) => Box::new(encoder),
                                Err(e) => {
                                    error!("Failed to create encoder device: {}", e);
                                    return;
                                }
                            }
                        }
                        #[cfg(feature = "libvda")]
                        VideoBackendType::LibvdaVd => {
                            error!("Invalid backend for encoder");
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
#[cfg(feature = "video-encoder")]
struct EosBufferManager {
    stream_id: u32,
    eos_buffer: Option<u32>,
    client_awaits_eos: bool,
    responses: Vec<device::VideoEvtResponseType>,
}

#[cfg(feature = "video-encoder")]
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

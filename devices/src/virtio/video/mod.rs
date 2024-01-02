// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the virtio video encoder and decoder devices.
//! The current implementation uses [v3 RFC] of the virtio-video protocol.
//!
//! [v3 RFC]: https://markmail.org/thread/wxdne5re7aaugbjg

use std::collections::BTreeMap;
use std::thread;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
#[cfg(feature = "video-encoder")]
use base::info;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use data_model::Le32;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;

use crate::virtio::copy_config;
use crate::virtio::virtio_device::VirtioDevice;
use crate::virtio::DeviceType;
use crate::virtio::Interrupt;
use crate::virtio::Queue;

#[macro_use]
mod macros;
mod async_cmd_desc_map;
mod command;
mod control;
#[cfg(feature = "video-decoder")]
mod decoder;
pub mod device;
#[cfg(feature = "video-encoder")]
mod encoder;
mod error;
mod event;
mod format;
mod params;
mod protocol;
mod resource;
mod response;
mod utils;
pub mod worker;

#[cfg(all(
    feature = "video-decoder",
    not(any(feature = "libvda", feature = "ffmpeg", feature = "vaapi"))
))]
compile_error!("The \"video-decoder\" feature requires at least one of \"ffmpeg\", \"libvda\" or \"vaapi\" to also be enabled.");

#[cfg(all(
    feature = "video-encoder",
    not(any(feature = "libvda", feature = "ffmpeg"))
))]
compile_error!("The \"video-encoder\" feature requires at least one of \"ffmpeg\" or \"libvda\" to also be enabled.");

#[cfg(feature = "ffmpeg")]
mod ffmpeg;
#[cfg(feature = "libvda")]
mod vda;

use command::ReadCmdError;
use device::Device;
use worker::Worker;

use super::device_constants::video::backend_supported_virtio_features;
use super::device_constants::video::virtio_video_config;
use super::device_constants::video::VideoBackendType;
use super::device_constants::video::VideoDeviceType;

// CMD_QUEUE_SIZE = max number of command descriptors for input and output queues
// Experimentally, it appears a stream allocates 16 input and 26 output buffers = 42 total
// For 8 simultaneous streams, 2 descs per buffer * 42 buffers * 8 streams = 672 descs
// Allocate 1024 to give some headroom in case of extra streams/buffers
//
// TODO(b/204055006): Make cmd queue size dependent of
// (max buf cnt for input + max buf cnt for output) * max descs per buffer * max nb of streams
const CMD_QUEUE_SIZE: u16 = 1024;

// EVENT_QUEUE_SIZE = max number of event descriptors for stream events like resolution changes
const EVENT_QUEUE_SIZE: u16 = 256;

const QUEUE_SIZES: &[u16] = &[CMD_QUEUE_SIZE, EVENT_QUEUE_SIZE];

/// An error indicating something went wrong in virtio-video's worker.
#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Cloning a descriptor failed
    #[error("failed to clone a descriptor: {0}")]
    CloneDescriptorFailed(SysError),
    /// No available descriptor in which an event is written to.
    #[error("no available descriptor in which an event is written to")]
    DescriptorNotAvailable,
    /// Creating a video device failed.
    #[cfg(feature = "video-decoder")]
    #[error("failed to create a video device: {0}")]
    DeviceCreationFailed(String),
    /// Making an EventAsync failed.
    #[error("failed to create an EventAsync: {0}")]
    EventAsyncCreationFailed(cros_async::AsyncError),
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
            let _ = kill_evt.signal();
        }
    }
}

pub fn build_config(backend: VideoBackendType) -> virtio_video_config {
    let mut device_name = [0u8; 32];
    match backend {
        #[cfg(feature = "libvda")]
        VideoBackendType::Libvda => device_name[0..6].copy_from_slice("libvda".as_bytes()),
        #[cfg(feature = "libvda")]
        VideoBackendType::LibvdaVd => device_name[0..8].copy_from_slice("libvdavd".as_bytes()),
        #[cfg(feature = "ffmpeg")]
        VideoBackendType::Ffmpeg => device_name[0..6].copy_from_slice("ffmpeg".as_bytes()),
        #[cfg(feature = "vaapi")]
        VideoBackendType::Vaapi => device_name[0..5].copy_from_slice("vaapi".as_bytes()),
    };
    virtio_video_config {
        version: Le32::from(0),
        max_caps_length: Le32::from(1024), // Set a big number
        max_resp_length: Le32::from(1024), // Set a big number
        device_name,
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

    fn device_type(&self) -> DeviceType {
        match &self.device_type {
            VideoDeviceType::Decoder => DeviceType::VideoDecoder,
            VideoDeviceType::Encoder => DeviceType::VideoEncoder,
        }
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.base_features | backend_supported_virtio_features(self.backend)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut cfg = build_config(self.backend);
        copy_config(data, 0, cfg.as_bytes_mut(), offset);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: BTreeMap<usize, Queue>,
    ) -> anyhow::Result<()> {
        if queues.len() != QUEUE_SIZES.len() {
            return Err(anyhow!(
                "wrong number of queues are passed: expected {}, actual {}",
                queues.len(),
                QUEUE_SIZES.len()
            ));
        }

        let (self_kill_evt, kill_evt) = Event::new()
            .and_then(|e| Ok((e.try_clone()?, e)))
            .context("failed to create kill Event pair")?;
        self.kill_evt = Some(self_kill_evt);

        let cmd_queue = queues.pop_first().unwrap().1;
        let event_queue = queues.pop_first().unwrap().1;
        let backend = self.backend;
        let resource_bridge = self
            .resource_bridge
            .take()
            .context("no resource bridge is passed")?;
        let mut worker = Worker::new(cmd_queue, interrupt.clone(), event_queue, interrupt);

        let worker_result = match &self.device_type {
            #[cfg(feature = "video-decoder")]
            VideoDeviceType::Decoder => thread::Builder::new()
                .name("v_video_decoder".to_owned())
                .spawn(move || {
                    let device: Box<dyn Device> =
                        match create_decoder_device(backend, resource_bridge, mem) {
                            Ok(value) => value,
                            Err(e) => {
                                error!("{}", e);
                                return;
                            }
                        };

                    if let Err(e) = worker.run(device, &kill_evt) {
                        error!("Failed to start decoder worker: {}", e);
                    };
                    // Don't return any information since the return value is never checked.
                }),
            #[cfg(feature = "video-encoder")]
            VideoDeviceType::Encoder => thread::Builder::new()
                .name("v_video_encoder".to_owned())
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
                        #[cfg(feature = "ffmpeg")]
                        VideoBackendType::Ffmpeg => {
                            let ffmpeg = encoder::backend::ffmpeg::FfmpegEncoder::new();

                            match encoder::EncoderDevice::new(ffmpeg, resource_bridge, mem) {
                                Ok(encoder) => Box::new(encoder),
                                Err(e) => {
                                    error!("Failed to create encoder device: {}", e);
                                    return;
                                }
                            }
                        }
                        #[cfg(feature = "vaapi")]
                        VideoBackendType::Vaapi => {
                            error!("The VA-API encoder is not supported yet");
                            return;
                        }
                    };

                    if let Err(e) = worker.run(device, &kill_evt) {
                        error!("Failed to start encoder worker: {}", e);
                    }
                }),
            #[allow(unreachable_patterns)]
            // A device will never be created for a device type not enabled
            device_type => unreachable!("Not compiled with {:?} enabled", device_type),
        };
        worker_result.with_context(|| {
            format!(
                "failed to spawn virtio_video worker for {:?}",
                &self.device_type
            )
        })?;
        Ok(())
    }
}

#[cfg(feature = "video-decoder")]
pub fn create_decoder_device(
    backend: VideoBackendType,
    resource_bridge: Tube,
    mem: GuestMemory,
) -> Result<Box<dyn Device>> {
    Ok(match backend {
        #[cfg(feature = "libvda")]
        VideoBackendType::Libvda => {
            let vda = decoder::backend::vda::LibvdaDecoder::new(libvda::decode::VdaImplType::Gavda)
                .map_err(|e| {
                    Error::DeviceCreationFailed(format!(
                        "Failed to initialize VDA for decoder: {}",
                        e
                    ))
                })?;
            Box::new(decoder::Decoder::new(vda, resource_bridge, mem))
        }
        #[cfg(feature = "libvda")]
        VideoBackendType::LibvdaVd => {
            let vda = decoder::backend::vda::LibvdaDecoder::new(libvda::decode::VdaImplType::Gavd)
                .map_err(|e| {
                    Error::DeviceCreationFailed(format!(
                        "Failed to initialize VD for decoder: {}",
                        e
                    ))
                })?;
            Box::new(decoder::Decoder::new(vda, resource_bridge, mem))
        }
        #[cfg(feature = "ffmpeg")]
        VideoBackendType::Ffmpeg => {
            let ffmpeg = decoder::backend::ffmpeg::FfmpegDecoder::new();
            Box::new(decoder::Decoder::new(ffmpeg, resource_bridge, mem))
        }
        #[cfg(feature = "vaapi")]
        VideoBackendType::Vaapi => {
            let va = decoder::backend::vaapi::VaapiDecoder::new().map_err(|e| {
                Error::DeviceCreationFailed(format!(
                    "Failed to initialize VA-API driver for decoder: {}",
                    e
                ))
            })?;
            Box::new(decoder::Decoder::new(va, resource_bridge, mem))
        }
    })
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

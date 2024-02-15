// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A ffmpeg-based software decoder backend for crosvm. Since it does not require any particular
//! harware, it can provide fake hardware acceleration decoding to any guest and is mostly useful in
//! order to work on the virtio-video specification, or to implement guest decoder code from the
//! comfort of a workstation.
//!
//! This backend is supposed to serve as the reference implementation for decoding backends in
//! crosvm. As such it is fairly complete and exposes all the features and memory types that crosvm
//! support.
//!
//! The code in this main module provides the actual implementation and is free of unsafe code. Safe
//! abstractions over the ffmpeg libraries are provided in sub-modules, one per ffmpeg library we
//! want to support.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Weak;

use ::ffmpeg::avcodec::*;
use ::ffmpeg::swscale::*;
use ::ffmpeg::*;
use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::info;
use base::warn;
use base::MappedRegion;
use base::MemoryMappingArena;
use thiserror::Error as ThisError;

use crate::virtio::video::decoder::backend::*;
use crate::virtio::video::ffmpeg::GuestResourceToAvFrameError;
use crate::virtio::video::ffmpeg::MemoryMappingAvBufferSource;
use crate::virtio::video::ffmpeg::TryAsAvFrameExt;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::FormatRange;
use crate::virtio::video::format::FrameFormat;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::Profile;
use crate::virtio::video::resource::BufferHandle;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;
use crate::virtio::video::utils::EventQueue;
use crate::virtio::video::utils::OutputQueue;
use crate::virtio::video::utils::SyncEventQueue;

/// Structure maintaining a mapping for an encoded input buffer that can be used as a libavcodec
/// buffer source. It also sends a `NotifyEndOfBitstreamBuffer` event when dropped.
struct InputBuffer {
    /// Memory mapping to the encoded input data.
    mapping: MemoryMappingArena,
    /// Resource ID that we will signal using `NotifyEndOfBitstreamBuffer` upon destruction.
    resource_id: u32,
    /// Pointer to the event queue to send the `NotifyEndOfBitstreamBuffer` event to. The event
    /// will not be sent if the pointer becomes invalid.
    event_queue: Weak<SyncEventQueue<DecoderEvent>>,
}

impl Drop for InputBuffer {
    fn drop(&mut self) {
        match self.event_queue.upgrade() {
            None => (),
            // If the event queue is still valid, send the event signaling we can be reused.
            Some(event_queue) => event_queue
                .queue_event(DecoderEvent::NotifyEndOfBitstreamBuffer(self.resource_id))
                .unwrap_or_else(|e| {
                    error!("cannot send end of input buffer notification: {:#}", e)
                }),
        }
    }
}

impl AvBufferSource for InputBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.mapping.as_ptr()
    }

    fn len(&self) -> usize {
        self.mapping.size()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Types of input job we can receive from the crosvm decoder code.
enum CodecJob {
    Packet(AvPacket<'static>),
    Flush,
}

/// A crosvm decoder needs to go through a number if setup stages before being able to decode, and
/// can require some setup to be redone when a dynamic resolution change occurs. This enum ensures
/// that the data associated with a given state only exists when we actually are in this state.
enum SessionState {
    /// Waiting for libavcodec to tell us the resolution of the stream.
    AwaitingInitialResolution,
    /// Waiting for the client to call `set_output_buffer_count`.
    AwaitingBufferCount,
    /// Decoding and producing frames.
    Decoding {
        output_queue: OutputQueue,
        format_converter: SwConverter,
    },
    /// Dynamic Resolution Change - we can still accept buffers in the old
    /// format, but are waiting for new parameters before doing any decoding.
    Drc,
}

/// A decoder session for the ffmpeg backend.
pub struct FfmpegDecoderSession {
    /// Queue of events waiting to be read by the client.
    event_queue: Arc<SyncEventQueue<DecoderEvent>>,

    /// FIFO of jobs submitted by the client and waiting to be performed.
    codec_jobs: VecDeque<CodecJob>,
    /// Whether we are currently flushing.
    is_flushing: bool,

    /// Current state of the session.
    state: SessionState,
    /// Visible size of the decoded frames (width, height).
    current_visible_res: (usize, usize),

    /// The libav context for this session.
    context: AvCodecContext,
    /// The last frame to have been decoded, waiting to be copied into an output buffer and sent
    /// to the client.
    avframe: Option<AvFrame>,
}

#[derive(Debug, ThisError)]
enum TrySendFrameError {
    #[error("error while converting frame: {0}")]
    CannotConvertFrame(#[from] ConversionError),
    #[error("error while constructing AvFrame: {0}")]
    IntoAvFrame(#[from] GuestResourceToAvFrameError),
    #[error("error while sending picture ready event: {0}")]
    BrokenPipe(#[from] base::Error),
}

#[derive(Debug, ThisError)]
enum TryReceiveFrameError {
    #[error("error creating AvFrame: {0}")]
    CreateAvFrame(#[from] AvFrameError),
    #[error("error queueing flush completed event: {0}")]
    CannotQueueFlushEvent(#[from] base::Error),
    #[error("error while changing resolution: {0}")]
    ChangeResolutionError(#[from] ChangeResolutionError),
}

#[derive(Debug, ThisError)]
enum TrySendPacketError {
    #[error("error while sending input packet to libavcodec: {0}")]
    AvError(#[from] AvError),
}

#[derive(Debug, ThisError)]
enum TryDecodeError {
    #[error("error while sending packet: {0}")]
    SendPacket(#[from] TrySendPacketError),
    #[error("error while trying to send decoded frame: {0}")]
    SendFrameError(#[from] TrySendFrameError),
    #[error("error while receiving frame: {0}")]
    ReceiveFrame(#[from] TryReceiveFrameError),
}

#[derive(Debug, ThisError)]
enum ChangeResolutionError {
    #[error("error queueing event: {0}")]
    QueueEventFailed(#[from] base::Error),
    #[error("unexpected state during resolution change")]
    UnexpectedState,
}

impl FfmpegDecoderSession {
    /// Queue an event for the client to receive.
    fn queue_event(&mut self, event: DecoderEvent) -> base::Result<()> {
        self.event_queue.queue_event(event)
    }

    /// Start the resolution change process, buffers will now be of size `new_visible_res`.
    fn change_resolution(
        &mut self,
        new_visible_res: (usize, usize),
    ) -> Result<(), ChangeResolutionError> {
        info!("resolution changed to {:?}", new_visible_res);

        // Ask the client for new buffers.
        self.queue_event(DecoderEvent::ProvidePictureBuffers {
            min_num_buffers: std::cmp::max(self.context.as_ref().refs, 0) as u32 + 1,
            width: new_visible_res.0 as i32,
            height: new_visible_res.1 as i32,
            visible_rect: Rect {
                left: 0,
                top: 0,
                right: new_visible_res.0 as i32,
                bottom: new_visible_res.1 as i32,
            },
        })?;

        self.current_visible_res = new_visible_res;

        // Drop our output queue and wait for the new number of output buffers.
        self.state = match self.state {
            SessionState::AwaitingInitialResolution => SessionState::AwaitingBufferCount,
            SessionState::Decoding { .. } => SessionState::Drc,
            _ => return Err(ChangeResolutionError::UnexpectedState),
        };

        Ok(())
    }

    /// Try to send one input packet to the codec.
    ///
    /// Returns `true` if a packet has successfully been queued, `false` if it could not be, either
    /// because all pending work has already been queued or because the codec could not accept more
    /// input at the moment.
    fn try_send_packet(
        &mut self,
        input_packet: &AvPacket<'static>,
    ) -> Result<bool, TrySendPacketError> {
        match self.context.try_send_packet(input_packet) {
            Ok(true) => Ok(true),
            // The codec cannot take more input at the moment, we'll try again after we receive some
            // frames.
            Ok(false) => Ok(false),
            // This should happen only if we attempt to submit data while flushing.
            Err(AvError(AVERROR_EOF)) => Ok(false),
            // If we got invalid data, keep going in hope that we will catch a valid state later.
            Err(AvError(AVERROR_INVALIDDATA)) => {
                warn!("Invalid data in stream, ignoring...");
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Try to run the next input job, if any.
    ///
    /// Returns `true` if the next job has been submitted, `false` if it could not be, either
    /// because all pending work has already been queued or because the codec could not accept more
    /// input at the moment.
    fn try_send_input_job(&mut self) -> Result<bool, TrySendPacketError> {
        // Do not process any more input while we are flushing.
        if self.is_flushing {
            return Ok(false);
        }

        let mut next_job = match self.codec_jobs.pop_front() {
            // No work to do at the moment.
            None => return Ok(false),
            Some(job) => job,
        };

        match &mut next_job {
            CodecJob::Packet(input_packet) => {
                let res = self.try_send_packet(input_packet)?;
                match res {
                    // The input buffer has been processed so we can drop it.
                    true => drop(next_job),
                    // The codec cannot accept new input for now, put the job back into the queue.
                    false => self.codec_jobs.push_front(next_job),
                }

                Ok(res)
            }
            CodecJob::Flush => {
                // Just set the is_flushing flag for now. We will send the actual flush command when
                // `try_receive_frame` returns `TryAgain`. This should probably not be necessary but
                // we sometimes miss the last frame if we send the flush command to libavcodec
                // earlier (which looks like a bug with libavcodec but needs to be confirmed).
                self.is_flushing = true;

                Ok(true)
            }
        }
    }

    /// Try to receive a frame from the codec and store it until we emit the corresponding
    /// `PictureReady` decoder event.
    ///
    /// Returns `true` if a frame was successfully retrieved, or false if no frame was available at
    /// the time, a decoded frame is already waiting to be returned to the client, or the decoder
    /// needs more input data to proceed further.
    fn try_receive_frame(&mut self) -> Result<bool, TryReceiveFrameError> {
        let mut avframe = match self.avframe {
            // We already have a frame waiting. Wait until it is sent to process the next one.
            Some(_) => return Ok(false),
            None => AvFrame::new()?,
        };

        match self.context.try_receive_frame(&mut avframe) {
            Ok(TryReceiveResult::Received) => {
                // Now check whether the resolution of the stream has changed.
                let new_visible_res = (avframe.width as usize, avframe.height as usize);
                if new_visible_res != self.current_visible_res {
                    self.change_resolution(new_visible_res)?;
                }

                self.avframe = Some(avframe);

                Ok(true)
            }
            Ok(TryReceiveResult::TryAgain) => {
                if self.is_flushing {
                    // Start flushing. `try_receive_frame` will return `FlushCompleted` when the
                    // flush is completed. `TryAgain` will not be returned again until the flush is
                    // completed.
                    match self.context.flush_decoder() {
                        // Call ourselves again so we can process the flush.
                        Ok(()) => self.try_receive_frame(),
                        Err(err) => {
                            self.is_flushing = false;
                            self.queue_event(DecoderEvent::FlushCompleted(Err(
                                VideoError::BackendFailure(err.into()),
                            )))?;
                            Ok(false)
                        }
                    }
                } else {
                    // The codec is not ready to output a frame yet.
                    Ok(false)
                }
            }
            Ok(TryReceiveResult::FlushCompleted) => {
                self.is_flushing = false;
                self.queue_event(DecoderEvent::FlushCompleted(Ok(())))?;
                self.context.reset();
                Ok(false)
            }
            // If we got invalid data, keep going in hope that we will catch a valid state later.
            Err(AvError(AVERROR_INVALIDDATA)) => {
                warn!("Invalid data in stream, ignoring...");
                Ok(false)
            }
            Err(av_err) => {
                // This is a decoding error, so signal it using a `NotifyError` event to reflect the
                // same asynchronous flow as a hardware decoder would.
                if let Err(e) = self.event_queue.queue_event(DecoderEvent::NotifyError(
                    VideoError::BackendFailure(av_err.into()),
                )) {
                    error!("failed to notify error: {}", e);
                }
                Ok(false)
            }
        }
    }

    /// Try to send a pending decoded frame to the client by copying its content into an output
    /// buffer.
    ///
    /// This can only be done if `self.avframe` contains a decoded frame, and an output buffer is
    /// ready to be written into.
    ///
    /// Returns `true` if a frame has been emitted, `false` if the conditions were not met for it to
    /// happen yet.
    fn try_send_frame(&mut self) -> Result<bool, TrySendFrameError> {
        let (output_queue, format_converter) = match &mut self.state {
            SessionState::Decoding {
                output_queue,
                format_converter,
            } => (output_queue, format_converter),
            // Frames can only be emitted if we are actively decoding.
            _ => return Ok(false),
        };

        let avframe = match self.avframe.take() {
            // No decoded frame available at the moment.
            None => return Ok(false),
            Some(avframe) => avframe,
        };

        let (picture_buffer_id, target_buffer) = match output_queue.try_get_ready_buffer() {
            None => {
                // Keep the decoded frame since we don't have a destination buffer to process it.
                self.avframe = Some(avframe);
                return Ok(false);
            }
            Some(buffer) => buffer,
        };

        // Prepare the picture ready event that we will emit once the frame is written into the
        // target buffer.
        let avframe_ref = avframe.as_ref();
        let picture_ready_event = DecoderEvent::PictureReady {
            picture_buffer_id: picture_buffer_id as i32,
            timestamp: avframe_ref.pts as u64,
            visible_rect: Rect {
                left: 0,
                top: 0,
                right: avframe_ref.width,
                bottom: avframe_ref.height,
            },
        };

        // Convert the frame into the target buffer and emit the picture ready event.
        format_converter.convert(
            &avframe,
            &mut target_buffer.try_as_av_frame(MemoryMappingAvBufferSource::from)?,
        )?;
        self.event_queue.queue_event(picture_ready_event)?;

        Ok(true)
    }

    /// Try to progress as much as possible with decoding.
    ///
    /// Our pipeline has three stages: send encoded input to libavcodec, receive decoded frames from
    /// libavcodec, and copy decoded frames into output buffers sent to the client. This method
    /// calls these three stages in a loop for as long as at least one makes progress.
    fn try_decode(&mut self) -> Result<(), TryDecodeError> {
        // Try to make the pipeline progress as long as one of the stages can move forward
        while self.try_send_frame()? || self.try_receive_frame()? || self.try_send_input_job()? {}

        Ok(())
    }
}

impl DecoderSession for FfmpegDecoderSession {
    fn set_output_parameters(&mut self, buffer_count: usize, format: Format) -> VideoResult<()> {
        match self.state {
            // It is valid to set an output format before the the initial DRC, but we won't do
            // anything with it.
            SessionState::AwaitingInitialResolution => Ok(()),
            SessionState::AwaitingBufferCount | SessionState::Drc => {
                let avcontext = self.context.as_ref();

                let dst_pix_format: AvPixelFormat =
                    format.try_into().map_err(|_| VideoError::InvalidFormat)?;

                self.state = SessionState::Decoding {
                    output_queue: OutputQueue::new(buffer_count),
                    format_converter: SwConverter::new(
                        avcontext.width as usize,
                        avcontext.height as usize,
                        avcontext.pix_fmt,
                        dst_pix_format.pix_fmt(),
                    )
                    .context("while setting output parameters")
                    .map_err(VideoError::BackendFailure)?,
                };
                Ok(())
            }
            _ => Err(VideoError::BackendFailure(anyhow!(
                "invalid state while calling set_output_parameters"
            ))),
        }
    }

    fn decode(
        &mut self,
        resource_id: u32,
        timestamp: u64,
        resource: GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()> {
        let input_buffer = InputBuffer {
            mapping: resource
                .get_mapping(offset as usize, bytes_used as usize)
                .context("while mapping input buffer")
                .map_err(VideoError::BackendFailure)?,
            resource_id,
            event_queue: Arc::downgrade(&self.event_queue),
        };

        let avbuffer = AvBuffer::new(input_buffer)
            .context("while creating AvPacket")
            .map_err(VideoError::BackendFailure)?;

        let avpacket = AvPacket::new_owned(timestamp as i64, avbuffer);

        self.codec_jobs.push_back(CodecJob::Packet(avpacket));

        self.try_decode()
            .context("while decoding")
            .map_err(VideoError::BackendFailure)
    }

    fn flush(&mut self) -> VideoResult<()> {
        if self.is_flushing {
            Err(VideoError::BackendFailure(anyhow!(
                "flush is already in progress"
            )))
        } else {
            self.codec_jobs.push_back(CodecJob::Flush);
            self.try_decode()
                .context("while flushing")
                .map_err(VideoError::BackendFailure)
        }
    }

    fn reset(&mut self) -> VideoResult<()> {
        // Reset the codec.
        self.context.reset();

        // Drop all currently pending jobs.
        self.codec_jobs.clear();

        // Drop the queued output buffers.
        self.clear_output_buffers()?;

        self.queue_event(DecoderEvent::ResetCompleted(Ok(())))
            .context("while resetting")
            .map_err(VideoError::BackendFailure)
    }

    fn clear_output_buffers(&mut self) -> VideoResult<()> {
        // Cancel any ongoing flush.
        self.is_flushing = false;

        // Drop all output buffers we currently hold.
        if let SessionState::Decoding { output_queue, .. } = &mut self.state {
            output_queue.clear_ready_buffers();
        }

        // Drop the currently decoded frame.
        self.avframe = None;

        // Drop all decoded frames signaled as ready and cancel any reported flush.
        self.event_queue.retain(|event| {
            !matches!(
                event,
                DecoderEvent::PictureReady { .. } | DecoderEvent::FlushCompleted(_)
            )
        });

        Ok(())
    }

    fn event_pipe(&self) -> &dyn AsRawDescriptor {
        self.event_queue.as_ref()
    }

    fn use_output_buffer(
        &mut self,
        picture_buffer_id: i32,
        resource: GuestResource,
    ) -> VideoResult<()> {
        let output_queue = match &mut self.state {
            // It is valid to receive buffers before the the initial DRC, but we won't decode
            // anything into them.
            SessionState::AwaitingInitialResolution => return Ok(()),
            SessionState::Decoding { output_queue, .. } => output_queue,
            // Receiving buffers during DRC is valid, but we won't use them and can just drop them.
            SessionState::Drc => return Ok(()),
            _ => {
                error!("use_output_buffer: invalid state");
                return Ok(());
            }
        };

        output_queue
            .import_buffer(picture_buffer_id as u32, resource)
            .context("while importing output buffer")
            .map_err(VideoError::BackendFailure)?;
        self.try_decode()
            .context("while importing output buffer")
            .map_err(VideoError::BackendFailure)
    }

    fn reuse_output_buffer(&mut self, picture_buffer_id: i32) -> VideoResult<()> {
        let output_queue = match &mut self.state {
            // It is valid to receive buffers before the the initial DRC, but we won't decode
            // anything into them.
            SessionState::AwaitingInitialResolution => return Ok(()),
            SessionState::Decoding { output_queue, .. } => output_queue,
            // Reusing buffers during DRC is valid, but we won't use them and can just drop them.
            SessionState::Drc => return Ok(()),
            _ => {
                return Err(VideoError::BackendFailure(anyhow!(
                    "invalid state while calling reuse_output_buffer"
                )))
            }
        };

        output_queue
            .reuse_buffer(picture_buffer_id as u32)
            .context("while reusing output buffer")
            .map_err(VideoError::BackendFailure)?;
        self.try_decode()
            .context("while reusing output buffer")
            .map_err(VideoError::BackendFailure)
    }

    fn read_event(&mut self) -> VideoResult<DecoderEvent> {
        self.event_queue
            .dequeue_event()
            .context("while reading decoder event")
            .map_err(VideoError::BackendFailure)
    }
}

pub struct FfmpegDecoder {
    codecs: BTreeMap<Format, AvCodec>,
}

impl FfmpegDecoder {
    /// Create a new ffmpeg decoder backend instance.
    pub fn new() -> Self {
        // Find all the decoders supported by libav and store them.
        let codecs = AvCodecIterator::new()
            .filter_map(|codec| {
                if !codec.is_decoder() {
                    return None;
                }

                let codec_name = codec.name();

                // Only keep processing the decoders we are interested in. These are all software
                // decoders, but nothing prevents us from supporting hardware-accelerated ones
                // (e.g. *_qsv for VAAPI-based acceleration) in the future!
                let format = match codec_name {
                    "h264" => Format::H264,
                    "vp8" => Format::VP8,
                    "vp9" => Format::VP9,
                    "hevc" => Format::Hevc,
                    _ => return None,
                };

                // We require custom buffer allocators, so ignore codecs that are not capable of
                // using them.
                if codec.capabilities() & AV_CODEC_CAP_DR1 == 0 {
                    warn!(
                        "Skipping codec {} due to lack of DR1 capability.",
                        codec_name
                    );
                    return None;
                }

                Some((format, codec))
            })
            .collect();

        Self { codecs }
    }
}

impl DecoderBackend for FfmpegDecoder {
    type Session = FfmpegDecoderSession;

    fn get_capabilities(&self) -> Capability {
        // The virtio device only supports NV12 for now it seems...
        const SUPPORTED_OUTPUT_FORMATS: [Format; 1] = [Format::NV12];

        let mut in_formats = vec![];
        let mut profiles_map: BTreeMap<Format, Vec<Profile>> = Default::default();
        let mut levels: BTreeMap<Format, Vec<Level>> = Default::default();
        for (&format, codec) in &self.codecs {
            let profile_iter = codec.profile_iter();
            let profiles = match format {
                Format::H264 => {
                    // We only support Level 1.0 for H.264.
                    // TODO Do we? Why?
                    levels.insert(format, vec![Level::H264_1_0]);

                    profile_iter
                        .filter_map(|p| {
                            match p.profile() {
                                FF_PROFILE_H264_BASELINE => Some(Profile::H264Baseline),
                                FF_PROFILE_H264_MAIN => Some(Profile::H264Main),
                                FF_PROFILE_H264_EXTENDED => Some(Profile::H264Extended),
                                FF_PROFILE_H264_HIGH => Some(Profile::H264High),
                                FF_PROFILE_H264_HIGH_10 => Some(Profile::H264High10),
                                FF_PROFILE_H264_HIGH_422 => Some(Profile::H264High422),
                                FF_PROFILE_H264_HIGH_444_PREDICTIVE => {
                                    Some(Profile::H264High444PredictiveProfile)
                                }
                                FF_PROFILE_H264_STEREO_HIGH => Some(Profile::H264StereoHigh),
                                FF_PROFILE_H264_MULTIVIEW_HIGH => Some(Profile::H264MultiviewHigh),
                                // TODO H264ScalableBaseline and H264ScalableHigh have no libav
                                // equivalents?
                                _ => None,
                            }
                        })
                        .collect()
                }
                Format::VP8 => {
                    // FFmpeg has no VP8 profiles, for some reason...
                    vec![
                        Profile::VP8Profile0,
                        Profile::VP8Profile1,
                        Profile::VP8Profile2,
                        Profile::VP8Profile3,
                    ]
                }
                Format::VP9 => profile_iter
                    .filter_map(|p| match p.profile() {
                        FF_PROFILE_VP9_0 => Some(Profile::VP9Profile0),
                        FF_PROFILE_VP9_1 => Some(Profile::VP9Profile1),
                        FF_PROFILE_VP9_2 => Some(Profile::VP9Profile2),
                        FF_PROFILE_VP9_3 => Some(Profile::VP9Profile3),
                        _ => None,
                    })
                    .collect(),
                Format::Hevc => profile_iter
                    .filter_map(|p| match p.profile() {
                        FF_PROFILE_HEVC_MAIN => Some(Profile::HevcMain),
                        FF_PROFILE_HEVC_MAIN_10 => Some(Profile::HevcMain10),
                        FF_PROFILE_HEVC_MAIN_STILL_PICTURE => Some(Profile::HevcMainStillPicture),
                        _ => None,
                    })
                    .collect(),
                _ => unreachable!("Unhandled format {:?}", format),
            };

            profiles_map.insert(format, profiles);

            in_formats.push(FormatDesc {
                mask: !(u64::MAX << SUPPORTED_OUTPUT_FORMATS.len()),
                format,
                frame_formats: vec![FrameFormat {
                    // These frame sizes are arbitrary, but avcodec does not seem to have any
                    // specific restriction in that regard (or any way to query the supported
                    // resolutions).
                    width: FormatRange {
                        min: 64,
                        max: 16384,
                        step: 1,
                    },
                    height: FormatRange {
                        min: 64,
                        max: 16384,
                        step: 1,
                    },
                    bitrates: Default::default(),
                }],
                plane_align: max_buffer_alignment() as u32,
            });
        }

        // We support all output formats through the use of swscale().
        let out_formats = SUPPORTED_OUTPUT_FORMATS
            .iter()
            .map(|&format| FormatDesc {
                mask: !(u64::MAX << in_formats.len()),
                format,
                frame_formats: vec![FrameFormat {
                    // These frame sizes are arbitrary, but avcodec does not seem to have any
                    // specific restriction in that regard (or any way to query the supported
                    // resolutions).
                    width: FormatRange {
                        min: 64,
                        max: 16384,
                        step: 1,
                    },
                    height: FormatRange {
                        min: 64,
                        max: 16384,
                        step: 1,
                    },
                    bitrates: Default::default(),
                }],
                plane_align: max_buffer_alignment() as u32,
            })
            .collect::<Vec<_>>();

        Capability::new(in_formats, out_formats, profiles_map, levels)
    }

    fn new_session(&mut self, format: Format) -> VideoResult<Self::Session> {
        let codec = self.codecs.get(&format).ok_or(VideoError::InvalidFormat)?;
        let context = codec
            // TODO we should use a custom `get_buffer` function that renders directly into the
            // target buffer if the output format is directly supported by libavcodec. Right now
            // libavcodec is allocating its own frame buffers, which forces us to perform a copy.
            .build_decoder()
            .and_then(|b| b.build())
            .context("while creating new session")
            .map_err(VideoError::BackendFailure)?;
        Ok(FfmpegDecoderSession {
            codec_jobs: Default::default(),
            is_flushing: false,
            state: SessionState::AwaitingInitialResolution,
            event_queue: Arc::new(
                EventQueue::new()
                    .context("while creating decoder session")
                    .map_err(VideoError::BackendFailure)?
                    .into(),
            ),
            context,
            current_visible_res: (0, 0),
            avframe: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;

    #[test]
    fn test_get_capabilities() {
        let decoder = FfmpegDecoder::new();
        let caps = decoder.get_capabilities();
        assert!(!caps.input_formats().is_empty());
        assert!(!caps.output_formats().is_empty());
    }

    #[test]
    fn test_decode_h264_guestmem_to_guestmem() {
        decode_h264_generic(
            &mut FfmpegDecoder::new(),
            build_guest_mem_handle,
            build_guest_mem_handle,
        );
    }

    // Decode using guest memory input and virtio object output buffers.
    #[test]
    fn test_decode_h264_guestmem_to_object() {
        decode_h264_generic(
            &mut FfmpegDecoder::new(),
            build_guest_mem_handle,
            build_object_handle,
        );
    }

    // Decode using virtio object input and guest memory output buffers.
    #[test]
    fn test_decode_h264_object_to_guestmem() {
        decode_h264_generic(
            &mut FfmpegDecoder::new(),
            build_object_handle,
            build_guest_mem_handle,
        );
    }

    // Decode using virtio object input and output buffers.
    #[test]
    fn test_decode_h264_object_to_object() {
        decode_h264_generic(
            &mut FfmpegDecoder::new(),
            build_object_handle,
            build_object_handle,
        );
    }
}

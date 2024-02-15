// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::os::raw::c_int;
use std::ptr;
use std::sync::Arc;
use std::sync::Weak;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::AsRawDescriptor;
use base::MappedRegion;
use base::MemoryMappingArena;
use ffmpeg::avcodec::AvBufferSource;
use ffmpeg::avcodec::AvCodec;
use ffmpeg::avcodec::AvCodecContext;
use ffmpeg::avcodec::AvCodecIterator;
use ffmpeg::avcodec::AvFrame;
use ffmpeg::avcodec::AvPacket;
use ffmpeg::avcodec::Dimensions;
use ffmpeg::avcodec::TryReceiveResult;
use ffmpeg::max_buffer_alignment;
use ffmpeg::AVPictureType_AV_PICTURE_TYPE_I;
use ffmpeg::AVRational;
use ffmpeg::AV_PKT_FLAG_KEY;

use crate::virtio::video::encoder::backend::Encoder;
use crate::virtio::video::encoder::backend::EncoderSession;
use crate::virtio::video::encoder::EncoderCapabilities;
use crate::virtio::video::encoder::EncoderEvent;
use crate::virtio::video::encoder::InputBufferId;
use crate::virtio::video::encoder::OutputBufferId;
use crate::virtio::video::encoder::SessionConfig;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::ffmpeg::TryAsAvFrameExt;
use crate::virtio::video::format::Bitrate;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::FormatRange;
use crate::virtio::video::format::FrameFormat;
use crate::virtio::video::format::Profile;
use crate::virtio::video::resource::BufferHandle;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;
use crate::virtio::video::utils::EventQueue;
use crate::virtio::video::utils::SyncEventQueue;

/// Structure wrapping a backing memory mapping for an input frame that can be used as a libavcodec
/// buffer source. It also sends a `ProcessedInputBuffer` event when dropped.
struct InputBuffer {
    /// Memory mapping to the input frame.
    mapping: MemoryMappingArena,
    /// Bistream ID that will be sent as part of the `ProcessedInputBuffer` event.
    buffer_id: InputBufferId,
    /// Pointer to the event queue to send the `ProcessedInputBuffer` event to. The event will
    /// not be sent if the pointer becomes invalid.
    event_queue: Weak<SyncEventQueue<EncoderEvent>>,
}

impl Drop for InputBuffer {
    fn drop(&mut self) {
        match self.event_queue.upgrade() {
            None => (),
            // If the event queue is still valid, send the event signaling we can be reused.
            Some(event_queue) => event_queue
                .queue_event(EncoderEvent::ProcessedInputBuffer { id: self.buffer_id })
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

enum CodecJob {
    Frame(AvFrame),
    Flush,
}

pub struct FfmpegEncoderSession {
    /// Queue of events waiting to be read by the client.
    event_queue: Arc<SyncEventQueue<EncoderEvent>>,

    /// FIFO of jobs submitted by the client and waiting to be performed.
    codec_jobs: VecDeque<CodecJob>,
    /// Queue of (unfilled) output buffers to fill with upcoming encoder output.
    output_queue: VecDeque<(OutputBufferId, MemoryMappingArena)>,
    /// `true` if a flush is pending. While a pending flush exist, input buffers are temporarily
    /// held on and not sent to the encoder. An actual flush call will be issued when we run out of
    /// output buffers (to defend against FFmpeg bugs), and we'll try to receive outputs again
    /// until we receive another code indicating the flush has completed, at which point this
    /// flag will be reset.
    is_flushing: bool,

    /// The libav context for this session.
    context: AvCodecContext,

    next_input_buffer_id: InputBufferId,
    next_output_buffer_id: OutputBufferId,
}

impl FfmpegEncoderSession {
    /// Try to send one input frame to the codec for encode.
    ///
    /// Returns `Ok(true)` if the frame was successfully queued, `Ok(false)` if the frame was not
    /// queued due to the queue being full or an in-progress flushing, and `Err` in case of errors.
    fn try_send_input_job(&mut self) -> VideoResult<bool> {
        // When a flush is queued, drain buffers.
        if self.is_flushing {
            return Ok(false);
        }

        match self.codec_jobs.front() {
            Some(CodecJob::Frame(b)) => {
                let result = self
                    .context
                    .try_send_frame(b)
                    .context("while sending frame")
                    .map_err(VideoError::BackendFailure);
                // This look awkward but we have to do it like this since VideoResult doesn't
                // implement PartialEq.
                if let Ok(false) = result {
                } else {
                    self.codec_jobs.pop_front().unwrap();
                }
                result
            }
            Some(CodecJob::Flush) => {
                self.codec_jobs.pop_front().unwrap();

                // Queue a flush. The actual flush will be performed when receive returns EAGAIN.
                self.is_flushing = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Try to retrieve one encoded packet from the codec, and if success, deliver it to the guest.
    ///
    /// Returns `Ok(true)` if the packet was successfully retrieved and the guest was signaled,
    /// `Ok(false)` if there's no full packet available right now, and `Err` in case of error.
    fn try_receive_packet(&mut self) -> VideoResult<bool> {
        let (buffer_id, out_buf) = match self.output_queue.front_mut() {
            Some(p) => p,
            None => return Ok(false),
        };

        let mut packet = AvPacket::empty();

        match self
            .context
            .try_receive_packet(&mut packet)
            .context("while receiving packet")
        {
            Ok(TryReceiveResult::TryAgain) => {
                if !self.is_flushing {
                    return Ok(false);
                }

                // Flush the encoder, then move on to draining.
                if let Err(err) = self.context.flush_encoder() {
                    self.is_flushing = false;
                    self.event_queue
                        .queue_event(EncoderEvent::FlushResponse { flush_done: false })
                        .context("while flushing")
                        .map_err(VideoError::BackendFailure)?;
                    return Err(err)
                        .context("while flushing")
                        .map_err(VideoError::BackendFailure);
                }
                self.try_receive_packet()
            }
            Ok(TryReceiveResult::FlushCompleted) => {
                self.is_flushing = false;
                self.event_queue
                    .queue_event(EncoderEvent::FlushResponse { flush_done: true })
                    .map_err(Into::into)
                    .map_err(VideoError::BackendFailure)?;
                self.context.reset();
                Ok(false)
            }
            Ok(TryReceiveResult::Received) => {
                let packet_size = packet.as_ref().size as usize;
                if packet_size > out_buf.size() {
                    return Err(VideoError::BackendFailure(anyhow!(
                        "encoded packet does not fit in output buffer"
                    )));
                }
                // SAFETY:
                // Safe because packet.as_ref().data and out_buf.as_ptr() are valid references and
                // we did bound check above.
                unsafe {
                    ptr::copy_nonoverlapping(packet.as_ref().data, out_buf.as_ptr(), packet_size);
                }
                self.event_queue
                    .queue_event(EncoderEvent::ProcessedOutputBuffer {
                        id: *buffer_id,
                        bytesused: packet.as_ref().size as _,
                        keyframe: (packet.as_ref().flags as u32 & AV_PKT_FLAG_KEY) != 0,
                        timestamp: packet.as_ref().dts as _,
                    })
                    .map_err(Into::into)
                    .map_err(VideoError::BackendFailure)?;
                self.output_queue.pop_front();
                Ok(true)
            }
            Err(e) => Err(VideoError::BackendFailure(e)),
        }
    }

    /// Try to progress through the encoding pipeline, either by sending input frames or by
    /// retrieving output packets and delivering them to the guest.
    fn try_encode(&mut self) -> VideoResult<()> {
        // Go through the pipeline stages as long as it makes some kind of progress.
        loop {
            let mut progress = false;
            // Use |= instead of || to avoid short-circuiting, which is harmless but makes the
            // execution order weird.
            progress |= self.try_send_input_job()?;
            progress |= self.try_receive_packet()?;
            if !progress {
                break;
            }
        }
        Ok(())
    }
}

impl EncoderSession for FfmpegEncoderSession {
    fn encode(
        &mut self,
        resource: GuestResource,
        timestamp: u64,
        force_keyframe: bool,
    ) -> VideoResult<InputBufferId> {
        let buffer_id = self.next_input_buffer_id;
        self.next_input_buffer_id = buffer_id.wrapping_add(1);

        let mut frame: AvFrame = resource
            .try_as_av_frame(|mapping| InputBuffer {
                mapping,
                buffer_id,
                event_queue: Arc::downgrade(&self.event_queue),
            })
            .context("while creating input AvFrame")
            .map_err(VideoError::BackendFailure)?;

        if force_keyframe {
            frame.set_pict_type(AVPictureType_AV_PICTURE_TYPE_I);
        }
        frame.set_pts(timestamp as i64);
        self.codec_jobs.push_back(CodecJob::Frame(frame));
        self.try_encode()?;

        Ok(buffer_id)
    }

    fn use_output_buffer(
        &mut self,
        resource: GuestResourceHandle,
        offset: u32,
        size: u32,
    ) -> VideoResult<OutputBufferId> {
        let buffer_id = self.next_output_buffer_id;
        self.next_output_buffer_id = buffer_id.wrapping_add(1);

        let mapping = resource
            .get_mapping(offset as usize, size as usize)
            .context("while mapping output buffer")
            .map_err(VideoError::BackendFailure)?;

        self.output_queue.push_back((buffer_id, mapping));
        self.try_encode()?;
        Ok(buffer_id)
    }

    fn flush(&mut self) -> VideoResult<()> {
        if self.is_flushing {
            return Err(VideoError::BackendFailure(anyhow!(
                "flush is already in progress"
            )));
        }
        self.codec_jobs.push_back(CodecJob::Flush);
        self.try_encode()?;
        Ok(())
    }

    fn request_encoding_params_change(
        &mut self,
        bitrate: Bitrate,
        framerate: u32,
    ) -> VideoResult<()> {
        match bitrate {
            Bitrate::Cbr { target } => {
                self.context.set_bit_rate(target as u64);
            }
            Bitrate::Vbr { target, peak } => {
                self.context.set_bit_rate(target as u64);
                self.context.set_max_bit_rate(peak as u64);
            }
        }
        // TODO(b/241492607): support fractional frame rates.
        self.context.set_time_base(AVRational {
            num: 1,
            den: framerate as c_int,
        });
        Ok(())
    }

    fn event_pipe(&self) -> &dyn AsRawDescriptor {
        self.event_queue.as_ref()
    }

    fn read_event(&mut self) -> VideoResult<EncoderEvent> {
        self.event_queue
            .dequeue_event()
            .context("while reading encoder event")
            .map_err(VideoError::BackendFailure)
    }
}

pub struct FfmpegEncoder {
    codecs: BTreeMap<Format, AvCodec>,
}

impl FfmpegEncoder {
    /// Create a new ffmpeg encoder backend instance.
    pub fn new() -> Self {
        // Find all the encoders supported by libav and store them.
        let codecs = AvCodecIterator::new()
            .filter_map(|codec| {
                if !codec.is_encoder() {
                    return None;
                }

                let codec_name = codec.name();

                // Only retain software encoders we know with their corresponding format. Other
                // encoder might depend on hardware (e.g. *_qsv) which we can't use.
                let format = match codec_name {
                    "libx264" => Format::H264,
                    "libvpx" => Format::VP8,
                    "libvpx-vp9" => Format::VP9,
                    "libx265" => Format::Hevc,
                    _ => return None,
                };

                Some((format, codec))
            })
            .collect();

        Self { codecs }
    }
}

impl Encoder for FfmpegEncoder {
    type Session = FfmpegEncoderSession;

    fn query_capabilities(&self) -> VideoResult<EncoderCapabilities> {
        let codecs = &self.codecs;
        let mut format_idx = BTreeMap::new();
        let mut input_format_descs = vec![];
        let output_format_descs = codecs
            .iter()
            .enumerate()
            .map(|(i, (&format, codec))| {
                let mut in_formats = 0;
                for in_format in codec.pixel_format_iter() {
                    if let Ok(in_format) = Format::try_from(in_format) {
                        let idx = format_idx.entry(in_format).or_insert_with(|| {
                            let idx = input_format_descs.len();
                            input_format_descs.push(FormatDesc {
                                mask: 0,
                                format: in_format,
                                frame_formats: vec![FrameFormat {
                                    // These frame sizes are arbitrary, but avcodec does not seem to
                                    // have any specific restriction in that regard (or any way to
                                    // query the supported resolutions).
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
                            idx
                        });
                        input_format_descs[*idx].mask |= 1 << i;
                        in_formats |= 1 << *idx;
                    }
                }
                FormatDesc {
                    mask: in_formats,
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
                }
            })
            .collect();
        // TODO(ishitatsuyuki): right now we haven't plumbed the profile handling yet and will use
        //                      a hard coded set of profiles. Make this support more profiles when
        //                      we implement the conversion between virtio and ffmpeg profiles.
        let coded_format_profiles = codecs
            .iter()
            .map(|(&format, _codec)| {
                (
                    format,
                    match format {
                        Format::H264 => vec![Profile::H264Baseline],
                        Format::Hevc => vec![Profile::HevcMain],
                        Format::VP8 => vec![Profile::VP8Profile0],
                        Format::VP9 => vec![Profile::VP9Profile0],
                        _ => vec![],
                    },
                )
            })
            .collect();
        let caps = EncoderCapabilities {
            input_format_descs,
            output_format_descs,
            coded_format_profiles,
        };

        Ok(caps)
    }

    fn start_session(&mut self, config: SessionConfig) -> VideoResult<Self::Session> {
        let dst_format = config
            .dst_params
            .format
            .ok_or(VideoError::InvalidOperation)?;
        let codec = self
            .codecs
            .get(&dst_format)
            .ok_or(VideoError::InvalidFormat)?;
        let pix_fmt = config
            .src_params
            .format
            .ok_or(VideoError::InvalidOperation)?
            .try_into()
            .map_err(|_| VideoError::InvalidFormat)?;
        let context = codec
            .build_encoder()
            .and_then(|mut b| {
                b.set_pix_fmt(pix_fmt);
                b.set_dimensions(Dimensions {
                    width: config.src_params.frame_width,
                    height: config.src_params.frame_height,
                });
                b.set_time_base(AVRational {
                    num: 1,
                    den: config.frame_rate as _,
                });
                b.build()
            })
            .context("while creating new session")
            .map_err(VideoError::BackendFailure)?;
        let session = FfmpegEncoderSession {
            event_queue: Arc::new(
                EventQueue::new()
                    .context("while creating encoder session")
                    .map_err(VideoError::BackendFailure)?
                    .into(),
            ),
            codec_jobs: Default::default(),
            output_queue: Default::default(),
            is_flushing: false,
            context,
            next_input_buffer_id: 0,
            next_output_buffer_id: 0,
        };
        session
            .event_queue
            .queue_event(EncoderEvent::RequireInputBuffers {
                input_count: 4,
                input_frame_height: config.src_params.frame_height,
                input_frame_width: config.src_params.frame_width,
                output_buffer_size: 16 * 1024 * 1024,
            })
            .context("while sending buffer request")
            .map_err(VideoError::BackendFailure)?;
        Ok(session)
    }

    fn stop_session(&mut self, _session: Self::Session) -> VideoResult<()> {
        // Just Drop.
        Ok(())
    }
}

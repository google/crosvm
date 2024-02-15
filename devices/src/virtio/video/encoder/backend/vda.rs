// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use anyhow::anyhow;
use anyhow::Context;
use base::error;
use base::warn;
use base::AsRawDescriptor;
use base::IntoRawDescriptor;
use libvda::encode::EncodeCapabilities;
use libvda::encode::VeaImplType;
use libvda::encode::VeaInstance;

use super::*;
use crate::virtio::video::encoder::*;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::Bitrate;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::FormatRange;
use crate::virtio::video::format::FrameFormat;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::Profile;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;

impl From<Bitrate> for libvda::encode::Bitrate {
    fn from(bitrate: Bitrate) -> Self {
        libvda::encode::Bitrate {
            mode: match bitrate {
                Bitrate::Vbr { .. } => libvda::encode::BitrateMode::VBR,
                Bitrate::Cbr { .. } => libvda::encode::BitrateMode::CBR,
            },
            target: bitrate.target(),
            peak: match &bitrate {
                // No need to specify peak if mode is CBR.
                Bitrate::Cbr { .. } => 0,
                Bitrate::Vbr { peak, .. } => *peak,
            },
        }
    }
}

/// A VDA encoder backend that can be passed to `EncoderDevice::new` in order to create a working
/// encoder.
pub struct LibvdaEncoder {
    instance: VeaInstance,
    capabilities: EncoderCapabilities,
}

impl LibvdaEncoder {
    pub fn new() -> VideoResult<Self> {
        let instance = VeaInstance::new(VeaImplType::Gavea)?;

        let EncodeCapabilities {
            input_formats,
            output_formats,
        } = instance.get_capabilities();

        if input_formats.is_empty() || output_formats.is_empty() {
            error!("No input or output formats.");
            return Err(VideoError::InvalidFormat);
        }

        let input_format_descs: Vec<FormatDesc> = input_formats
            .iter()
            .map(|input_format| {
                let format = match input_format {
                    libvda::PixelFormat::NV12 => Format::NV12,
                    libvda::PixelFormat::YV12 => Format::YUV420,
                };

                // VEA's GetSupportedProfiles does not return resolution information.
                // The input formats are retrieved by querying minigbm.
                // TODO(alexlau): Populate this with real information.

                FormatDesc {
                    mask: !(u64::MAX << output_formats.len()),
                    format,
                    frame_formats: vec![FrameFormat {
                        width: FormatRange {
                            min: 2,
                            max: 4096,
                            step: 1,
                        },
                        height: FormatRange {
                            min: 2,
                            max: 4096,
                            step: 1,
                        },
                        bitrates: vec![FormatRange {
                            min: 0,
                            max: 8000,
                            step: 1,
                        }],
                    }],
                    plane_align: 1,
                }
            })
            .collect();

        if !input_format_descs
            .iter()
            .any(|fd| fd.format == Format::NV12)
        {
            // NV12 is currently the only supported pixel format for libvda.
            error!("libvda encoder does not support NV12.");
            return Err(VideoError::InvalidFormat);
        }

        struct ParsedFormat {
            profiles: Vec<Profile>,
            max_width: u32,
            max_height: u32,
        }
        let mut parsed_formats: BTreeMap<Format, ParsedFormat> = BTreeMap::new();

        for output_format in output_formats.iter() {
            // TODO(alexlau): Consider using `max_framerate_numerator` and
            // `max_framerate_denominator`.
            let libvda::encode::OutputProfile {
                profile: libvda_profile,
                max_width,
                max_height,
                ..
            } = output_format;

            let profile = match Profile::from_libvda_profile(*libvda_profile) {
                Some(p) => p,
                None => {
                    warn!("Skipping unsupported libvda profile: {:?}", libvda_profile);
                    continue;
                }
            };

            match parsed_formats.entry(profile.to_format()) {
                Entry::Occupied(mut occupied_entry) => {
                    let parsed_format = occupied_entry.get_mut();
                    parsed_format.profiles.push(profile);
                    // If we get different libvda profiles of the same VIRTIO_VIDEO_FORMAT
                    // (Format) that have different max resolutions or bitrates, take the
                    // minimum between all of the different profiles.
                    parsed_format.max_width = std::cmp::min(*max_width, parsed_format.max_width);
                    parsed_format.max_height = std::cmp::min(*max_height, parsed_format.max_height);
                }
                Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(ParsedFormat {
                        profiles: vec![profile],
                        max_width: *max_width,
                        max_height: *max_height,
                    });
                }
            }
        }

        let mut output_format_descs = vec![];
        let mut coded_format_profiles = BTreeMap::new();
        for (format, parsed_format) in parsed_formats.into_iter() {
            let ParsedFormat {
                mut profiles,
                max_width,
                max_height,
            } = parsed_format;

            output_format_descs.push(FormatDesc {
                mask: !(u64::MAX << output_formats.len()),
                format,
                frame_formats: vec![FrameFormat {
                    width: FormatRange {
                        min: 2,
                        max: max_width,
                        step: 1,
                    },
                    height: FormatRange {
                        min: 2,
                        max: max_height,
                        step: 1,
                    },
                    bitrates: vec![FormatRange {
                        min: 0,
                        max: 8000,
                        step: 1,
                    }],
                }],
                plane_align: 1,
            });

            profiles.sort_unstable();
            coded_format_profiles.insert(format, profiles);
        }

        Ok(LibvdaEncoder {
            instance,
            capabilities: EncoderCapabilities {
                input_format_descs,
                output_format_descs,
                coded_format_profiles,
            },
        })
    }
}

impl Encoder for LibvdaEncoder {
    type Session = LibvdaEncoderSession;

    fn query_capabilities(&self) -> VideoResult<EncoderCapabilities> {
        Ok(self.capabilities.clone())
    }

    fn start_session(&mut self, config: SessionConfig) -> VideoResult<LibvdaEncoderSession> {
        if config.dst_params.format.is_none() {
            return Err(VideoError::InvalidArgument);
        }

        let input_format = match config
            .src_params
            .format
            .ok_or(VideoError::InvalidArgument)?
        {
            Format::NV12 => libvda::PixelFormat::NV12,
            Format::YUV420 => libvda::PixelFormat::YV12,
            unsupported_format => {
                error!("Unsupported libvda format: {}", unsupported_format);
                return Err(VideoError::InvalidArgument);
            }
        };

        let output_profile = match config.dst_profile.to_libvda_profile() {
            Some(p) => p,
            None => {
                error!("Unsupported libvda profile");
                return Err(VideoError::InvalidArgument);
            }
        };

        let config = libvda::encode::Config {
            input_format,
            input_visible_width: config.src_params.frame_width,
            input_visible_height: config.src_params.frame_height,
            output_profile,
            bitrate: config.dst_bitrate.into(),
            initial_framerate: if config.frame_rate == 0 {
                None
            } else {
                Some(config.frame_rate)
            },
            h264_output_level: config.dst_h264_level.map(|level| {
                // This value is aligned to the H264 standard definition of SPS.level_idc.
                match level {
                    Level::H264_1_0 => 10,
                    Level::H264_1_1 => 11,
                    Level::H264_1_2 => 12,
                    Level::H264_1_3 => 13,
                    Level::H264_2_0 => 20,
                    Level::H264_2_1 => 21,
                    Level::H264_2_2 => 22,
                    Level::H264_3_0 => 30,
                    Level::H264_3_1 => 31,
                    Level::H264_3_2 => 32,
                    Level::H264_4_0 => 40,
                    Level::H264_4_1 => 41,
                    Level::H264_4_2 => 42,
                    Level::H264_5_0 => 50,
                    Level::H264_5_1 => 51,
                }
            }),
        };

        let session = self.instance.open_session(config)?;

        Ok(LibvdaEncoderSession {
            session,
            next_input_buffer_id: 1,
            next_output_buffer_id: 1,
        })
    }

    fn stop_session(&mut self, _session: LibvdaEncoderSession) -> VideoResult<()> {
        // Resources will be freed when `_session` is dropped.
        Ok(())
    }
}

pub struct LibvdaEncoderSession {
    session: libvda::encode::Session,
    next_input_buffer_id: InputBufferId,
    next_output_buffer_id: OutputBufferId,
}

impl EncoderSession for LibvdaEncoderSession {
    fn encode(
        &mut self,
        resource: GuestResource,
        timestamp: u64,
        force_keyframe: bool,
    ) -> VideoResult<InputBufferId> {
        let input_buffer_id = self.next_input_buffer_id;
        let desc = match resource.handle {
            GuestResourceHandle::VirtioObject(handle) => handle.desc,
            _ => {
                return Err(VideoError::BackendFailure(anyhow!(
                    "VDA backend only supports virtio object resources"
                )))
            }
        };

        let libvda_planes = resource
            .planes
            .iter()
            .map(|plane| libvda::FramePlane {
                offset: plane.offset as i32,
                stride: plane.stride as i32,
            })
            .collect::<Vec<_>>();

        self.session.encode(
            input_buffer_id as i32,
            // Steal the descriptor of the resource, as libvda will close it.
            desc.into_raw_descriptor(),
            &libvda_planes,
            timestamp as i64,
            force_keyframe,
        )?;

        self.next_input_buffer_id = self.next_input_buffer_id.wrapping_add(1);

        Ok(input_buffer_id)
    }

    fn use_output_buffer(
        &mut self,
        resource: GuestResourceHandle,
        offset: u32,
        size: u32,
    ) -> VideoResult<OutputBufferId> {
        let output_buffer_id = self.next_output_buffer_id;
        let desc = match resource {
            GuestResourceHandle::VirtioObject(handle) => handle.desc,
            _ => {
                return Err(VideoError::BackendFailure(anyhow!(
                    "VDA backend only supports virtio object resources"
                )))
            }
        };

        self.session.use_output_buffer(
            output_buffer_id as i32,
            // Steal the descriptor of the resource, as libvda will close it.
            desc.into_raw_descriptor(),
            offset,
            size,
        )?;

        self.next_output_buffer_id = self.next_output_buffer_id.wrapping_add(1);

        Ok(output_buffer_id)
    }

    fn flush(&mut self) -> VideoResult<()> {
        self.session
            .flush()
            .context("while flushing")
            .map_err(VideoError::BackendFailure)
    }

    fn request_encoding_params_change(
        &mut self,
        bitrate: Bitrate,
        framerate: u32,
    ) -> VideoResult<()> {
        self.session
            .request_encoding_params_change(bitrate.into(), framerate)
            .context("while requesting encoder parameter change")
            .map_err(VideoError::BackendFailure)
    }

    fn event_pipe(&self) -> &dyn AsRawDescriptor {
        self.session.pipe()
    }

    fn read_event(&mut self) -> VideoResult<EncoderEvent> {
        let event = self.session.read_event()?;

        use libvda::encode::Event::*;
        let encoder_event = match event {
            RequireInputBuffers {
                input_count,
                input_frame_width,
                input_frame_height,
                output_buffer_size,
            } => EncoderEvent::RequireInputBuffers {
                input_count,
                input_frame_width,
                input_frame_height,
                output_buffer_size,
            },
            ProcessedInputBuffer(id) => EncoderEvent::ProcessedInputBuffer { id: id as u32 },
            ProcessedOutputBuffer {
                output_buffer_id,
                payload_size,
                key_frame,
                timestamp,
                ..
            } => EncoderEvent::ProcessedOutputBuffer {
                id: output_buffer_id as u32,
                bytesused: payload_size,
                keyframe: key_frame,
                timestamp: timestamp as u64,
            },
            FlushResponse { flush_done } => EncoderEvent::FlushResponse { flush_done },
            NotifyError(err) => EncoderEvent::NotifyError {
                error: VideoError::BackendFailure(anyhow!(err)),
            },
        };

        Ok(encoder_event)
    }
}

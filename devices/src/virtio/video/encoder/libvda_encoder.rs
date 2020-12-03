// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs::File;

use libvda::encode::{EncodeCapabilities, VeaImplType, VeaInstance};

use base::{error, warn, IntoRawDescriptor};

use crate::virtio::video::encoder::encoder::*;
use crate::virtio::video::format::{Format, FormatDesc, FormatRange, FrameFormat, Level, Profile};

pub struct LibvdaEncoder {
    instance: VeaInstance,
    capabilities: EncoderCapabilities,
}

impl LibvdaEncoder {
    pub fn new() -> Result<Self> {
        let instance = VeaInstance::new(VeaImplType::Gavea)
            .map_err(|e| EncoderError::Implementation(Box::new(e)))?;

        let EncodeCapabilities {
            input_formats,
            output_formats,
        } = instance.get_capabilities();

        if input_formats.len() == 0 || output_formats.len() == 0 {
            error!("No input or output formats.");
            return Err(EncoderError::PlatformFailure);
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
                }
            })
            .collect();

        if input_format_descs
            .iter()
            .find(|fd| fd.format == Format::NV12)
            .is_none()
        {
            // NV12 is currently the only supported pixel format for libvda.
            error!("libvda encoder does not support NV12.");
            return Err(EncoderError::PlatformFailure);
        }

        struct ParsedFormat {
            profiles: Vec<Profile>,
            max_width: u32,
            max_height: u32,
        }
        let mut parsed_formats: BTreeMap<Format, ParsedFormat> = BTreeMap::new();

        for output_format in output_formats.iter() {
            // TODO(alexlau): Consider using `max_framerate_numerator` and `max_framerate_denominator`.
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

impl<'a> Encoder for &'a LibvdaEncoder {
    type Session = LibvdaEncoderSession<'a>;

    fn query_capabilities(&self) -> Result<EncoderCapabilities> {
        Ok(self.capabilities.clone())
    }

    fn start_session(&mut self, config: SessionConfig) -> Result<LibvdaEncoderSession<'a>> {
        if config.dst_params.format.is_none() {
            return Err(EncoderError::InvalidArgument);
        }

        let input_format = match config
            .src_params
            .format
            .ok_or(EncoderError::InvalidArgument)?
        {
            Format::NV12 => libvda::PixelFormat::NV12,
            Format::YUV420 => libvda::PixelFormat::YV12,
            unsupported_format => {
                error!("Unsupported libvda format: {}", unsupported_format);
                return Err(EncoderError::InvalidArgument);
            }
        };

        let output_profile = match config.dst_profile.to_libvda_profile() {
            Some(p) => p,
            None => {
                error!("Unsupported libvda profile");
                return Err(EncoderError::InvalidArgument);
            }
        };

        let config = libvda::encode::Config {
            input_format,
            input_visible_width: config.src_params.frame_width,
            input_visible_height: config.src_params.frame_height,
            output_profile,
            initial_bitrate: config.dst_bitrate,
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

        let session = self
            .instance
            .open_session(config)
            .map_err(|e| EncoderError::Implementation(Box::new(e)))?;

        Ok(LibvdaEncoderSession {
            session,
            next_input_buffer_id: 1,
            next_output_buffer_id: 1,
        })
    }

    fn stop_session(&mut self, _session: LibvdaEncoderSession) -> Result<()> {
        // Resources will be freed when `_session` is dropped.
        Ok(())
    }
}

pub struct LibvdaEncoderSession<'a> {
    session: libvda::encode::Session<'a>,
    next_input_buffer_id: InputBufferId,
    next_output_buffer_id: OutputBufferId,
}

impl<'a> EncoderSession for LibvdaEncoderSession<'a> {
    fn encode(
        &mut self,
        resource: File,
        planes: &[VideoFramePlane],
        timestamp: u64,
        force_keyframe: bool,
    ) -> Result<InputBufferId> {
        let input_buffer_id = self.next_input_buffer_id;

        let libvda_planes = planes
            .iter()
            .map(|plane| libvda::FramePlane {
                offset: plane.offset as i32,
                stride: plane.stride as i32,
            })
            .collect::<Vec<_>>();

        self.session
            .encode(
                input_buffer_id as i32,
                resource.into_raw_descriptor(),
                &libvda_planes,
                timestamp as i64,
                force_keyframe,
            )
            .map_err(|e| EncoderError::Implementation(Box::new(e)))?;

        self.next_input_buffer_id = self.next_input_buffer_id.wrapping_add(1);

        Ok(input_buffer_id)
    }

    fn use_output_buffer(&mut self, file: File, offset: u32, size: u32) -> Result<OutputBufferId> {
        let output_buffer_id = self.next_output_buffer_id;
        self.next_output_buffer_id = self.next_output_buffer_id.wrapping_add(1);

        self.session
            .use_output_buffer(
                output_buffer_id as i32,
                file.into_raw_descriptor(),
                offset,
                size,
            )
            .map_err(|e| EncoderError::Implementation(Box::new(e)))?;

        Ok(output_buffer_id)
    }

    fn flush(&mut self) -> Result<()> {
        self.session
            .flush()
            .map_err(|e| EncoderError::Implementation(Box::new(e)))
    }

    fn request_encoding_params_change(&mut self, bitrate: u32, framerate: u32) -> Result<()> {
        self.session
            .request_encoding_params_change(bitrate, framerate)
            .map_err(|e| EncoderError::Implementation(Box::new(e)))
    }

    fn event_pipe(&self) -> &File {
        self.session.pipe()
    }

    fn read_event(&mut self) -> Result<EncoderEvent> {
        let event = self
            .session
            .read_event()
            .map_err(|e| EncoderError::Implementation(Box::new(e)))?;

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
                error: EncoderError::Implementation(Box::new(err)),
            },
        };

        Ok(encoder_event)
    }
}

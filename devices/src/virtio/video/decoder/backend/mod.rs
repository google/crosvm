// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the interface that actual decoder devices need to
//! implement in order to provide video decoding capability to the guest.

use base::AsRawDescriptor;

use crate::virtio::video::decoder::Capability;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::Rect;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;

#[cfg(feature = "ffmpeg")]
pub mod ffmpeg;

#[cfg(feature = "vaapi")]
pub mod vaapi;
#[cfg(feature = "libvda")]
pub mod vda;

/// Contains the device's state for one playback session, i.e. one stream.
pub trait DecoderSession {
    /// Tell how many output buffers will be used for this session and which format they will carry.
    /// This method must be called after a `ProvidePictureBuffers` event is emitted, and before the
    /// first call to `use_output_buffer()`.
    fn set_output_parameters(&mut self, buffer_count: usize, format: Format) -> VideoResult<()>;

    /// Decode the compressed stream contained in [`offset`..`offset`+`bytes_used`] of the shared
    /// memory in the input `resource`.
    ///
    /// `resource_id` is the ID of the input resource. It will be signaled using the
    /// `NotifyEndOfBitstreamBuffer` once the input resource is not used anymore.
    ///
    /// `timestamp` is a timestamp that will be copied into the frames decoded from that input
    /// stream. Units are effectively free and provided by the input stream.
    ///
    /// The device takes ownership of `resource` and is responsible for closing it once it is not
    /// used anymore.
    ///
    /// The device will emit a `NotifyEndOfBitstreamBuffer` event with the `resource_id` value after
    /// the input buffer has been entirely processed.
    ///
    /// The device will emit a `PictureReady` event with the `timestamp` value for each picture
    /// produced from that input buffer.
    fn decode(
        &mut self,
        resource_id: u32,
        timestamp: u64,
        resource: GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()>;

    /// Flush the decoder device, i.e. finish processing all queued decode requests and emit frames
    /// for them.
    ///
    /// The device will emit a `FlushCompleted` event once the flush is done.
    fn flush(&mut self) -> VideoResult<()>;

    /// Reset the decoder device, i.e. cancel all pending decoding requests.
    ///
    /// The device will emit a `ResetCompleted` event once the reset is done.
    fn reset(&mut self) -> VideoResult<()>;

    /// Immediately release all buffers passed using `use_output_buffer()` and
    /// `reuse_output_buffer()`.
    fn clear_output_buffers(&mut self) -> VideoResult<()>;

    /// Returns the event pipe on which the availability of events will be signaled. Note that the
    /// returned value is borrowed and only valid as long as the session is alive.
    fn event_pipe(&self) -> &dyn AsRawDescriptor;

    /// Ask the device to use `resource` to store decoded frames according to its layout.
    /// `picture_buffer_id` is the ID of the picture that will be reproduced in `PictureReady`
    /// events using this buffer.
    ///
    /// The device takes ownership of `resource` and is responsible for closing it once the buffer
    /// is not used anymore (either when the session is closed, or a new set of buffers is provided
    /// for the session).
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id` field set to the
    /// same value as the argument of the same name when a frame has been decoded into that buffer.
    fn use_output_buffer(
        &mut self,
        picture_buffer_id: i32,
        resource: GuestResource,
    ) -> VideoResult<()>;

    /// Ask the device to reuse an output buffer previously passed to
    /// `use_output_buffer` and that has previously been returned to the decoder
    /// in a `PictureReady` event.
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id`
    /// field set to the same value as the argument of the same name when a
    /// frame has been decoded into that buffer.
    fn reuse_output_buffer(&mut self, picture_buffer_id: i32) -> VideoResult<()>;

    /// Blocking call to read a single event from the event pipe.
    fn read_event(&mut self) -> VideoResult<DecoderEvent>;
}

pub trait DecoderBackend {
    type Session: DecoderSession;

    /// Return the decoding capabilities for this backend instance.
    fn get_capabilities(&self) -> Capability;

    /// Create a new decoding session for the passed `format`.
    fn new_session(&mut self, format: Format) -> VideoResult<Self::Session>;
}

#[derive(Debug)]
pub enum DecoderEvent {
    /// Emitted when the device knows the buffer format it will need to decode frames, and how many
    /// buffers it will need. The decoder is supposed to call `set_output_parameters()` to confirm
    /// the pixel format and actual number of buffers used, and provide buffers of the requested
    /// dimensions using `use_output_buffer()`.
    ProvidePictureBuffers {
        min_num_buffers: u32,
        width: i32,
        height: i32,
        visible_rect: Rect,
    },
    /// Emitted when the decoder is done decoding a picture. `picture_buffer_id`
    /// corresponds to the argument of the same name passed to `use_output_buffer()`
    /// or `reuse_output_buffer()`. `bitstream_id` corresponds to the argument of
    /// the same name passed to `decode()` and can be used to match decoded frames
    /// to the input buffer they were produced from.
    PictureReady {
        picture_buffer_id: i32,
        timestamp: u64,
        visible_rect: Rect,
    },
    /// Emitted when an input buffer passed to `decode()` is not used by the
    /// device anymore and can be reused by the decoder. The parameter corresponds
    /// to the `timestamp` argument passed to `decode()`.
    NotifyEndOfBitstreamBuffer(u32),
    /// Emitted when a decoding error has occured.
    NotifyError(VideoError),
    /// Emitted after `flush()` has been called to signal that the flush is completed.
    FlushCompleted(VideoResult<()>),
    /// Emitted after `reset()` has been called to signal that the reset is completed.
    ResetCompleted(VideoResult<()>),
}

#[cfg(test)]
/// Shared functions that can be used to test individual backends.
mod tests {
    use std::time::Duration;

    use base::FromRawDescriptor;
    use base::MappedRegion;
    use base::MemoryMappingBuilder;
    use base::SafeDescriptor;
    use base::SharedMemory;
    use base::WaitContext;

    use super::*;
    use crate::virtio::video::format::FramePlane;
    use crate::virtio::video::resource::GuestMemArea;
    use crate::virtio::video::resource::GuestMemHandle;
    use crate::virtio::video::resource::VirtioObjectHandle;

    // Test video stream and its properties.
    const H264_STREAM: &[u8] = include_bytes!("test-25fps.h264");
    const H264_STREAM_WIDTH: i32 = 320;
    const H264_STREAM_HEIGHT: i32 = 240;
    const H264_STREAM_NUM_FRAMES: usize = 250;
    const H264_STREAM_CRCS: &str = include_str!("test-25fps.crc");

    /// Splits a H.264 annex B stream into chunks that are all guaranteed to contain a full frame
    /// worth of data.
    ///
    /// This is a pretty naive implementation that is only guaranteed to work with our test stream.
    /// We are not using `AVCodecParser` because it seems to modify the decoding context, which
    /// would result in testing conditions that diverge more from our real use case where parsing
    /// has already been done.
    struct H264NalIterator<'a> {
        stream: &'a [u8],
        pos: usize,
    }

    impl<'a> H264NalIterator<'a> {
        fn new(stream: &'a [u8]) -> Self {
            Self { stream, pos: 0 }
        }

        /// Returns the position of the start of the next frame in the stream.
        fn next_frame_pos(&self) -> Option<usize> {
            const H264_START_CODE: [u8; 4] = [0x0, 0x0, 0x0, 0x1];
            self.stream[self.pos + 1..]
                .windows(H264_START_CODE.len())
                .position(|window| window == H264_START_CODE)
                .map(|pos| self.pos + pos + 1)
        }

        /// Returns whether `slice` contains frame data, i.e. a header where the NAL unit type is
        /// 0x1 or 0x5.
        fn contains_frame(slice: &[u8]) -> bool {
            slice[4..].windows(4).any(|window| {
                window[0..3] == [0x0, 0x0, 0x1]
                    && (window[3] & 0x1f == 0x5 || window[3] & 0x1f == 0x1)
            })
        }
    }

    impl<'a> Iterator for H264NalIterator<'a> {
        type Item = &'a [u8];

        fn next(&mut self) -> Option<Self::Item> {
            match self.pos {
                cur_pos if cur_pos == self.stream.len() => None,
                cur_pos => loop {
                    self.pos = self.next_frame_pos().unwrap_or(self.stream.len());
                    let slice = &self.stream[cur_pos..self.pos];

                    // Keep advancing as long as we don't have frame data in our slice.
                    if Self::contains_frame(slice) || self.pos == self.stream.len() {
                        return Some(slice);
                    }
                },
            }
        }
    }

    // Build a virtio object handle from a linear memory area. This is useful to emulate the
    // scenario where we are decoding from or into virtio objects.
    #[allow(dead_code)]
    pub fn build_object_handle(mem: &SharedMemory) -> GuestResourceHandle {
        GuestResourceHandle::VirtioObject(VirtioObjectHandle {
            // SAFETY:
            // Safe because we are taking ownership of a just-duplicated FD.
            desc: unsafe {
                SafeDescriptor::from_raw_descriptor(base::clone_descriptor(mem).unwrap())
            },
            modifier: 0,
        })
    }

    // Build a guest memory handle from a linear memory area. This is useful to emulate the
    // scenario where we are decoding from or into guest memory.
    #[allow(dead_code)]
    pub fn build_guest_mem_handle(mem: &SharedMemory) -> GuestResourceHandle {
        GuestResourceHandle::GuestPages(GuestMemHandle {
            // SAFETY:
            // Safe because we are taking ownership of a just-duplicated FD.
            desc: unsafe {
                SafeDescriptor::from_raw_descriptor(base::clone_descriptor(mem).unwrap())
            },
            mem_areas: vec![GuestMemArea {
                offset: 0,
                length: mem.size() as usize,
            }],
        })
    }

    /// Full decoding test of a H.264 video, checking that the flow of events is happening as
    /// expected.
    pub fn decode_h264_generic<D, I, O>(
        decoder: &mut D,
        input_resource_builder: I,
        output_resource_builder: O,
    ) where
        D: DecoderBackend,
        I: Fn(&SharedMemory) -> GuestResourceHandle,
        O: Fn(&SharedMemory) -> GuestResourceHandle,
    {
        const NUM_OUTPUT_BUFFERS: usize = 4;
        const INPUT_BUF_SIZE: usize = 0x4000;
        const OUTPUT_BUFFER_SIZE: usize =
            (H264_STREAM_WIDTH * (H264_STREAM_HEIGHT + H264_STREAM_HEIGHT / 2)) as usize;
        let mut session = decoder
            .new_session(Format::H264)
            .expect("failed to create H264 decoding session.");
        let wait_ctx = WaitContext::new().expect("Failed to create wait context");
        wait_ctx
            .add(session.event_pipe(), 0u8)
            .expect("Failed to add event pipe to wait context");
        // Output buffers suitable for receiving NV12 frames for our stream.
        let output_buffers = (0..NUM_OUTPUT_BUFFERS)
            .map(|i| {
                SharedMemory::new(
                    format!("video-output-buffer-{}", i),
                    OUTPUT_BUFFER_SIZE as u64,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let input_shm = SharedMemory::new("video-input-buffer", INPUT_BUF_SIZE as u64).unwrap();
        let input_mapping = MemoryMappingBuilder::new(input_shm.size() as usize)
            .from_shared_memory(&input_shm)
            .build()
            .unwrap();

        let mut decoded_frames_count = 0usize;
        let mut expected_frames_crcs = H264_STREAM_CRCS.lines();

        let mut on_frame_decoded =
            |session: &mut D::Session, picture_buffer_id: i32, visible_rect: Rect| {
                assert_eq!(
                    visible_rect,
                    Rect {
                        left: 0,
                        top: 0,
                        right: H264_STREAM_WIDTH,
                        bottom: H264_STREAM_HEIGHT,
                    }
                );

                // Verify that the CRC of the decoded frame matches the expected one.
                let mapping = MemoryMappingBuilder::new(OUTPUT_BUFFER_SIZE)
                    .from_shared_memory(&output_buffers[picture_buffer_id as usize])
                    .build()
                    .unwrap();
                let mut frame_data = vec![0u8; mapping.size()];
                assert_eq!(
                    mapping.read_slice(&mut frame_data, 0).unwrap(),
                    mapping.size()
                );

                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&frame_data);
                let frame_crc = hasher.finalize();
                assert_eq!(
                    format!("{:08x}", frame_crc),
                    expected_frames_crcs
                        .next()
                        .expect("No CRC for decoded frame")
                );

                // We can recycle the frame now.
                session.reuse_output_buffer(picture_buffer_id).unwrap();
                decoded_frames_count += 1;
            };

        // Simple value by which we will multiply the frame number to obtain a fake timestamp.
        const TIMESTAMP_FOR_INPUT_ID_FACTOR: u64 = 1_000_000;
        for (input_id, slice) in H264NalIterator::new(H264_STREAM).enumerate() {
            let buffer_handle = input_resource_builder(&input_shm);
            input_mapping
                .write_slice(slice, 0)
                .expect("Failed to write stream data into input buffer.");
            session
                .decode(
                    input_id as u32,
                    input_id as u64 * TIMESTAMP_FOR_INPUT_ID_FACTOR,
                    buffer_handle,
                    0,
                    slice.len() as u32,
                )
                .expect("Call to decode() failed.");

            // Get all the events resulting from this submission.
            let mut events = Vec::new();
            while !wait_ctx.wait_timeout(Duration::ZERO).unwrap().is_empty() {
                events.push(session.read_event().unwrap());
            }

            // Our bitstream buffer should have been returned.
            let event_idx = events
                .iter()
                .position(|event| {
                    let input_id = input_id as u32;
                    matches!(event, DecoderEvent::NotifyEndOfBitstreamBuffer(index) if *index == input_id)
                })
                .unwrap();
            events.remove(event_idx);

            // After sending the first buffer we should get the initial resolution change event and
            // can provide the frames to decode into.
            if input_id == 0 {
                let event_idx = events
                    .iter()
                    .position(|event| {
                        matches!(
                            event,
                            DecoderEvent::ProvidePictureBuffers {
                                width: H264_STREAM_WIDTH,
                                height: H264_STREAM_HEIGHT,
                                visible_rect: Rect {
                                    left: 0,
                                    top: 0,
                                    right: H264_STREAM_WIDTH,
                                    bottom: H264_STREAM_HEIGHT,
                                },
                                ..
                            }
                        )
                    })
                    .unwrap();
                events.remove(event_idx);

                let out_format = Format::NV12;

                session
                    .set_output_parameters(NUM_OUTPUT_BUFFERS, out_format)
                    .unwrap();

                // Pass the buffers we will decode into.
                for (picture_buffer_id, buffer) in output_buffers.iter().enumerate() {
                    session
                        .use_output_buffer(
                            picture_buffer_id as i32,
                            GuestResource {
                                handle: output_resource_builder(buffer),
                                planes: vec![
                                    FramePlane {
                                        offset: 0,
                                        stride: H264_STREAM_WIDTH as usize,
                                        size: (H264_STREAM_WIDTH * H264_STREAM_HEIGHT) as usize,
                                    },
                                    FramePlane {
                                        offset: (H264_STREAM_WIDTH * H264_STREAM_HEIGHT) as usize,
                                        stride: H264_STREAM_WIDTH as usize,
                                        size: (H264_STREAM_WIDTH * H264_STREAM_HEIGHT) as usize,
                                    },
                                ],
                                width: H264_STREAM_WIDTH as _,
                                height: H264_STREAM_HEIGHT as _,
                                format: out_format,
                                guest_cpu_mappable: false,
                            },
                        )
                        .unwrap();
                }
            }

            // If we have remaining events, they must be decoded frames. Get them and recycle them.
            for event in events {
                match event {
                    DecoderEvent::PictureReady {
                        picture_buffer_id,
                        visible_rect,
                        ..
                    } => on_frame_decoded(&mut session, picture_buffer_id, visible_rect),
                    e => panic!("Unexpected event: {:?}", e),
                }
            }
        }

        session.flush().unwrap();

        // Keep getting frames until the final event, which should be `FlushCompleted`.
        let mut received_flush_completed = false;
        while !wait_ctx.wait_timeout(Duration::ZERO).unwrap().is_empty() {
            match session.read_event().unwrap() {
                DecoderEvent::PictureReady {
                    picture_buffer_id,
                    visible_rect,
                    ..
                } => on_frame_decoded(&mut session, picture_buffer_id, visible_rect),
                DecoderEvent::FlushCompleted(Ok(())) => {
                    received_flush_completed = true;
                    break;
                }
                e => panic!("Unexpected event: {:?}", e),
            }
        }

        // Confirm that we got the FlushCompleted event.
        assert!(received_flush_completed);

        // We should have read all the events for that session.
        assert_eq!(wait_ctx.wait_timeout(Duration::ZERO).unwrap().len(), 0);

        // We should not be expecting any more frame
        assert_eq!(expected_frames_crcs.next(), None);

        // Check that we decoded the expected number of frames.
        assert_eq!(decoded_frames_count, H264_STREAM_NUM_FRAMES);
    }
}

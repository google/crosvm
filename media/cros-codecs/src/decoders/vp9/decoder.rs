// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use anyhow::Result;
use log::debug;

use crate::decoders::vp9::backends::StatelessDecoderBackend;
use crate::decoders::vp9::parser::BitDepth;
use crate::decoders::vp9::parser::Frame;
use crate::decoders::vp9::parser::FrameType;
use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::Parser;
use crate::decoders::vp9::parser::Profile;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::picture::Vp9Picture;
use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::DynDecodedHandle;
use crate::decoders::Result as VideoDecoderResult;
use crate::decoders::VideoDecoder;
use crate::Resolution;

#[cfg(test)]
struct TestParams<T> {
    ready_pics: Vec<T>,
}

#[cfg(test)]
impl<T> TestParams<T> {
    fn save_ready_pics(&mut self, ready_pics: Vec<T>) {
        self.ready_pics.extend(ready_pics);
    }
}

#[cfg(test)]
impl<T> Default for TestParams<T> {
    fn default() -> Self {
        Self {
            ready_pics: Default::default(),
        }
    }
}

/// Represents where we are in the negotiation status. We assume ownership of
/// the incoming buffers in this special case so that clients do not have to do
/// the bookkeeping themselves.
enum NegotiationStatus {
    /// Still waiting for a key frame.
    NonNegotiated,

    /// Saw a key frame. Negotiation is possible until the next call to decode()
    Possible {
        key_frame: (u64, Box<Header>, Vec<u8>),
    },
    /// Processing the queued buffers.
    DrainingQueuedBuffers,
    /// Negotiated. Locks in the format until a new key frame is seen if that
    /// new key frame changes the stream parameters.
    Negotiated,
}

impl Default for NegotiationStatus {
    fn default() -> Self {
        Self::NonNegotiated
    }
}

pub struct Decoder<T: DecodedHandle<CodecData = Header>> {
    /// A parser to extract bitstream data and build frame data in turn
    parser: Parser,

    /// Whether the decoder should block on decode operations.
    blocking_mode: BlockingMode,

    /// The backend used for hardware acceleration.
    backend: Box<dyn StatelessDecoderBackend<Handle = T>>,

    /// Keeps track of whether the decoded format has been negotiated with the
    /// backend.
    negotiation_status: NegotiationStatus,

    /// The reference frames in use.
    reference_frames: [Option<T>; NUM_REF_FRAMES],

    /// The current resolution
    coded_resolution: Resolution,

    /// A queue with the pictures that are ready to be sent to the client.
    ready_queue: Vec<T>,

    /// Cached value for bit depth
    bit_depth: BitDepth,
    /// Cached value for profile
    profile: Profile,

    /// A monotonically increasing counter used to tag pictures in display
    /// order
    current_display_order: u64,

    #[cfg(test)]
    test_params: TestParams<T>,
}

impl<T: DecodedHandle<CodecData = Header> + DynDecodedHandle + 'static> Decoder<T> {
    /// Create a new codec backend for VP8.
    #[cfg(any(feature = "vaapi", test))]
    pub(crate) fn new(
        backend: Box<dyn StatelessDecoderBackend<Handle = T>>,
        blocking_mode: BlockingMode,
    ) -> Result<Self> {
        Ok(Self {
            backend,
            blocking_mode,
            parser: Default::default(),
            negotiation_status: Default::default(),
            reference_frames: Default::default(),
            coded_resolution: Default::default(),
            ready_queue: Default::default(),
            bit_depth: Default::default(),
            profile: Default::default(),
            current_display_order: Default::default(),

            #[cfg(test)]
            test_params: Default::default(),
        })
    }

    /// Replace a reference frame with `handle`.
    fn replace_reference(reference: &mut Option<T>, handle: &T) {
        *reference = Some(handle.clone());
    }

    fn update_references(
        reference_frames: &mut [Option<T>; NUM_REF_FRAMES],
        picture: &T,
        mut refresh_frame_flags: u8,
    ) -> Result<()> {
        #[allow(clippy::needless_range_loop)]
        for i in 0..NUM_REF_FRAMES {
            if (refresh_frame_flags & 1) == 1 {
                debug!("Replacing reference frame {}", i);
                Self::replace_reference(&mut reference_frames[i], picture)
            }

            refresh_frame_flags >>= 1;
        }

        Ok(())
    }

    fn block_on_one(&mut self) -> Result<()> {
        for handle in &self.ready_queue {
            if !self.backend.handle_is_ready(handle) {
                return self.backend.block_on_handle(handle).map_err(|e| anyhow!(e));
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn steal_pics_for_test(&mut self) {
        let frames = self.get_ready_frames();
        self.test_params.save_ready_pics(frames);
    }

    /// Returns the ready handles.
    fn get_ready_frames(&mut self) -> Vec<T> {
        let ready = self
            .ready_queue
            .iter()
            .filter(|&handle| self.backend.handle_is_ready(handle))
            .cloned()
            .collect::<Vec<_>>();

        self.ready_queue
            .retain(|handle| !self.backend.handle_is_ready(handle));

        ready
    }

    /// Handle a single frame.
    fn handle_frame(&mut self, frame: Frame<&dyn AsRef<[u8]>>, timestamp: u64) -> Result<T> {
        if frame.header.show_existing_frame() {
            // Frame to be shown. Unwrapping must produce a Picture, because the
            // spec mandates frame_to_show_map_idx references a valid entry in
            // the DPB
            let idx = usize::from(frame.header.frame_to_show_map_idx());
            let ref_frame = self.reference_frames[idx].as_ref().unwrap();

            // We are done, no further processing needed.
            Ok(ref_frame.clone())
        } else {
            // Otherwise, we must actually arrange to decode a frame
            let refresh_frame_flags = frame.header.refresh_frame_flags();

            let offset = frame.offset();
            let size = frame.size();

            let picture = Vp9Picture::new_vp9(frame.header, None, timestamp);

            let block = matches!(self.blocking_mode, BlockingMode::Blocking)
                || matches!(
                    self.negotiation_status,
                    NegotiationStatus::DrainingQueuedBuffers
                );

            let bitstream = &frame.bitstream.as_ref()[offset..offset + size];

            let decoded_handle = self
                .backend
                .submit_picture(
                    picture,
                    &self.reference_frames,
                    &bitstream,
                    timestamp,
                    block,
                )
                .map_err(|e| anyhow!(e))?;

            // Do DPB management
            Self::update_references(
                &mut self.reference_frames,
                &decoded_handle,
                refresh_frame_flags,
            )?;

            Ok(decoded_handle)
        }
    }

    fn negotiation_possible(&self, frame: &Frame<impl AsRef<[u8]>>) -> bool {
        let coded_resolution = self.coded_resolution;
        let hdr = &frame.header;
        let width = hdr.width();
        let height = hdr.height();
        let bit_depth = hdr.bit_depth();
        let profile = hdr.profile();

        if width == 0 || height == 0 {
            return false;
        }

        width != coded_resolution.width
            || height != coded_resolution.height
            || bit_depth != self.bit_depth
            || profile != self.profile
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn backend(&self) -> &dyn StatelessDecoderBackend<Handle = T> {
        self.backend.as_ref()
    }
}

impl<T: DecodedHandle<CodecData = Header> + DynDecodedHandle + 'static> VideoDecoder
    for Decoder<T>
{
    fn decode(
        &mut self,
        timestamp: u64,
        bitstream: &dyn AsRef<[u8]>,
    ) -> VideoDecoderResult<Vec<Box<dyn DynDecodedHandle>>> {
        let frames = self
            .parser
            .parse_chunk(|| bitstream)
            .map_err(|e| anyhow!(e))?;

        for frame in frames {
            if matches!(frame.header.frame_type(), FrameType::KeyFrame) {
                if self.negotiation_possible(&frame)
                    && matches!(self.negotiation_status, NegotiationStatus::Negotiated)
                {
                    self.negotiation_status = NegotiationStatus::NonNegotiated;
                }
            }

            let queued_key_frame = match &mut self.negotiation_status {
                NegotiationStatus::NonNegotiated => {
                    if matches!(frame.header.frame_type(), FrameType::KeyFrame) {
                        self.backend.poll(BlockingMode::Blocking)?;

                        self.backend.new_sequence(&frame.header)?;

                        let offset = frame.offset();
                        let size = frame.size();
                        let bitstream = frame.bitstream.as_ref()[offset..offset + size].to_vec();

                        self.coded_resolution = Resolution {
                            width: frame.header.width(),
                            height: frame.header.height(),
                        };

                        self.profile = frame.header.profile();
                        self.bit_depth = frame.header.bit_depth();

                        self.negotiation_status = NegotiationStatus::Possible {
                            key_frame: (timestamp, Box::new(frame.header), bitstream),
                        }
                    }

                    return Ok(vec![]);
                }

                NegotiationStatus::Possible { key_frame } => {
                    let key_frame = key_frame.clone();
                    self.negotiation_status = NegotiationStatus::DrainingQueuedBuffers;
                    Some(key_frame)
                }

                NegotiationStatus::DrainingQueuedBuffers | NegotiationStatus::Negotiated => None,
            };

            if let Some(queued_key_frame) = queued_key_frame {
                let (timestamp, header, bitstream) = queued_key_frame;
                let sz = bitstream.len();

                let bitstream = &bitstream as &dyn AsRef<[u8]>;

                let key_frame = Frame::new(bitstream, *header, 0, sz);

                let show_existing_frame = frame.header.show_existing_frame();
                let mut handle = self.handle_frame(key_frame, timestamp)?;

                if handle.picture().data.show_frame() || show_existing_frame {
                    let order = self.current_display_order;
                    handle.set_display_order(order);
                    self.current_display_order += 1;

                    self.ready_queue.push(handle);
                }

                self.negotiation_status = NegotiationStatus::Negotiated;
            }

            let show_existing_frame = frame.header.show_existing_frame();
            let mut handle = self.handle_frame(frame, timestamp)?;

            if self.backend.num_resources_left() == 0 {
                self.block_on_one()?;
            }

            self.backend.poll(self.blocking_mode)?;

            if handle.picture().data.show_frame() || show_existing_frame {
                let order = self.current_display_order;
                handle.set_display_order(order);
                self.current_display_order += 1;

                self.ready_queue.push(handle);
            }
        }

        #[cfg(test)]
        self.steal_pics_for_test();

        let ready_frames = self.get_ready_frames();

        Ok(ready_frames
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }

    fn flush(&mut self) -> VideoDecoderResult<Vec<Box<dyn DynDecodedHandle>>> {
        // Decode whatever is pending using the default format. Mainly covers
        // the rare case where only one buffer is sent.
        if let NegotiationStatus::Possible { key_frame } = &self.negotiation_status {
            let (timestamp, header, bitstream) = key_frame;

            let bitstream = &bitstream.clone() as &dyn AsRef<[u8]>;
            let sz = bitstream.as_ref().len();

            let header = header.as_ref().clone();

            let key_frame = Frame::new(bitstream, header, 0, sz);
            let timestamp = *timestamp;

            self.handle_frame(key_frame, timestamp)?;
        }

        self.backend.poll(BlockingMode::Blocking)?;

        #[cfg(test)]
        self.steal_pics_for_test();

        let pics = self.get_ready_frames();

        Ok(pics
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }

    fn negotiation_possible(&self) -> bool {
        matches!(self.negotiation_status, NegotiationStatus::Possible { .. })
    }

    fn num_resources_left(&self) -> Option<usize> {
        if matches!(self.negotiation_status, NegotiationStatus::NonNegotiated) {
            return None;
        }

        let left_in_the_backend = self.backend.num_resources_left();

        if let NegotiationStatus::Possible { .. } = &self.negotiation_status {
            Some(left_in_the_backend - 1)
        } else {
            Some(left_in_the_backend)
        }
    }

    fn num_resources_total(&self) -> usize {
        self.backend.num_resources_total()
    }

    fn coded_resolution(&self) -> Option<Resolution> {
        self.backend.coded_resolution()
    }

    fn poll(
        &mut self,
        blocking_mode: BlockingMode,
    ) -> VideoDecoderResult<Vec<Box<dyn DynDecodedHandle>>> {
        let handles = self.backend.poll(blocking_mode)?;

        Ok(handles
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;
    use std::io::Read;
    use std::io::Seek;

    use bytes::Buf;

    use crate::decoders::vp9::decoder::Decoder;
    use crate::decoders::vp9::parser::Header;
    use crate::decoders::BlockingMode;
    use crate::decoders::DecodedHandle;
    use crate::decoders::DynDecodedHandle;
    use crate::decoders::VideoDecoder;

    /// Read and return the data from the next IVF packet. Returns `None` if there is no more data
    /// to read.
    fn read_ivf_packet(cursor: &mut Cursor<&[u8]>) -> Option<Box<[u8]>> {
        if !cursor.has_remaining() {
            return None;
        }

        let len = cursor.get_u32_le();
        // Skip PTS.
        let _ = cursor.get_u64_le();

        let mut buf = vec![0u8; len as usize];
        cursor.read_exact(&mut buf).unwrap();

        Some(buf.into_boxed_slice())
    }

    pub fn run_decoding_loop<
        Handle: DecodedHandle<CodecData = Header> + DynDecodedHandle + 'static,
        F: FnMut(&mut Decoder<Handle>),
    >(
        decoder: &mut Decoder<Handle>,
        test_stream: &[u8],
        mut on_new_iteration: F,
    ) {
        let mut cursor = Cursor::new(test_stream);
        let mut frame_num = 0;

        // Skip the IVH header entirely.
        cursor.seek(std::io::SeekFrom::Start(32)).unwrap();

        while let Some(packet) = read_ivf_packet(&mut cursor) {
            let bitstream = packet.as_ref();
            decoder.decode(frame_num, &bitstream).unwrap();

            on_new_iteration(decoder);
            frame_num += 1;
        }

        decoder.flush().unwrap();

        let n_flushed = decoder.test_params.ready_pics.len();

        for _ in 0..n_flushed {
            on_new_iteration(decoder);
        }
    }

    pub fn process_ready_frames<Handle: DecodedHandle<CodecData = Header> + DynDecodedHandle>(
        decoder: &mut Decoder<Handle>,
        action: &mut dyn FnMut(&mut Decoder<Handle>, &Handle),
    ) {
        let ready_pics = decoder.test_params.ready_pics.drain(..).collect::<Vec<_>>();

        for handle in ready_pics {
            action(decoder, &handle);
        }
    }

    #[test]
    fn test_25fps_vp9() {
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-25fps.vp9");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let mut decoder = Decoder::new_dummy(blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 250);
        }
    }

    #[test]
    fn test_25fps_vp90_2_10_show_existing_frame2_vp9() {
        const TEST_STREAM: &[u8] =
            include_bytes!("test_data/vp90_2_10_show_existing_frame2.vp9.ivf");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let mut decoder = Decoder::new_dummy(blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 16);
        }
    }

    #[test]
    fn test_25fps_vp90_2_10_show_existing_frame_vp9() {
        const TEST_STREAM: &[u8] =
            include_bytes!("test_data/vp90-2-10-show-existing-frame.vp9.ivf");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let mut decoder = Decoder::new_dummy(blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 13);
        }
    }

    #[test]
    fn test_resolution_change_500frames_vp9() {
        const TEST_STREAM: &[u8] = include_bytes!("test_data/resolution_change_500frames-vp9.ivf");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let mut decoder = Decoder::new_dummy(blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 500);
        }
    }
}

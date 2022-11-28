// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use anyhow::Result;

use crate::decoders::vp8::backends::stateless::StatelessDecoderBackend;
use crate::decoders::vp8::parser::Frame;
use crate::decoders::vp8::parser::Header;
use crate::decoders::vp8::parser::Parser;
use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::DynDecodedHandle;
use crate::decoders::Picture;
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
        key_frame: (u64, Box<Header>, Vec<u8>, Box<Parser>),
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

    /// The picture used as the last reference picture.
    last_picture: Option<T>,
    /// The picture used as the golden reference picture.
    golden_ref_picture: Option<T>,
    /// The picture used as the alternate reference picture.
    alt_ref_picture: Option<T>,

    /// The current resolution
    coded_resolution: Resolution,

    /// A queue with the pictures that are ready to be sent to the client.
    ready_queue: Vec<T>,

    /// A monotonically increasing counter used to tag pictures in display
    /// order
    current_display_order: u64,

    #[cfg(test)]
    test_params: TestParams<T>,
}

impl<T: DecodedHandle<CodecData = Header> + DynDecodedHandle + 'static> Decoder<T> {
    /// Create a new codec backend for VP8.
    pub fn new(
        backend: Box<dyn StatelessDecoderBackend<Handle = T>>,
        blocking_mode: BlockingMode,
    ) -> Result<Self> {
        Ok(Self {
            backend,
            blocking_mode,
            // wait_keyframe: true,
            parser: Default::default(),
            negotiation_status: Default::default(),
            last_picture: Default::default(),
            golden_ref_picture: Default::default(),
            alt_ref_picture: Default::default(),
            coded_resolution: Default::default(),
            ready_queue: Default::default(),
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
        decoded_frame: &T,
        last_picture: &mut Option<T>,
        golden_ref_picture: &mut Option<T>,
        alt_ref_picture: &mut Option<T>,
    ) -> Result<()> {
        let header = &decoded_frame.picture().data;

        if header.key_frame() {
            Decoder::replace_reference(last_picture, decoded_frame);
            Decoder::replace_reference(golden_ref_picture, decoded_frame);
            Decoder::replace_reference(alt_ref_picture, decoded_frame);
        } else {
            if header.refresh_alternate_frame() {
                Decoder::replace_reference(alt_ref_picture, decoded_frame);
            } else {
                match header.copy_buffer_to_alternate() {
                    0 => { /* do nothing */ }

                    1 => {
                        if let Some(last_picture) = last_picture {
                            Decoder::replace_reference(alt_ref_picture, last_picture);
                        }
                    }

                    2 => {
                        if let Some(golden_ref) = golden_ref_picture {
                            Decoder::replace_reference(alt_ref_picture, golden_ref);
                        }
                    }

                    other => panic!("Invalid value: {}", other),
                }
            }

            if header.refresh_golden_frame() {
                Decoder::replace_reference(golden_ref_picture, decoded_frame);
            } else {
                match header.copy_buffer_to_golden() {
                    0 => { /* do nothing */ }

                    1 => {
                        if let Some(last_picture) = last_picture {
                            Decoder::replace_reference(golden_ref_picture, last_picture);
                        }
                    }

                    2 => {
                        if let Some(alt_ref) = alt_ref_picture {
                            Decoder::replace_reference(golden_ref_picture, alt_ref);
                        }
                    }

                    other => panic!("Invalid value: {}", other),
                }
            }

            if header.refresh_last() {
                Decoder::replace_reference(last_picture, decoded_frame);
            }
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
    fn handle_frame(
        &mut self,
        frame: Frame<&dyn AsRef<[u8]>>,
        timestamp: u64,
        queued_parser_state: Option<Parser>,
    ) -> Result<T> {
        let picture = Picture::new_vp8(frame.header, None, timestamp);

        let parser = match &queued_parser_state {
            Some(parser) => parser,
            None => &self.parser,
        };

        let block = matches!(self.blocking_mode, BlockingMode::Blocking)
            || matches!(
                self.negotiation_status,
                NegotiationStatus::DrainingQueuedBuffers
            );

        let decoded_handle = self
            .backend
            .submit_picture(
                picture,
                self.last_picture.as_ref(),
                self.golden_ref_picture.as_ref(),
                self.alt_ref_picture.as_ref(),
                frame.bitstream,
                parser,
                timestamp,
                block,
            )
            .map_err(|e| anyhow!(e))?;
        // .map_err(DecoderError::StatelessBackendError)?;

        // Do DPB management
        Self::update_references(
            &decoded_handle,
            &mut self.last_picture,
            &mut self.golden_ref_picture,
            &mut self.alt_ref_picture,
        )?;

        Ok(decoded_handle)
    }

    fn negotiation_possible(&self, frame: &Frame<impl AsRef<[u8]>>) -> bool {
        let coded_resolution = self.coded_resolution;
        let hdr = &frame.header;
        let width = u32::from(hdr.width());
        let height = u32::from(hdr.height());

        width != coded_resolution.width || height != coded_resolution.height
    }

    #[cfg(test)]
    pub fn backend(&self) -> &dyn StatelessDecoderBackend<Handle = T> {
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
        let frame = self.parser.parse_frame(bitstream).map_err(|e| anyhow!(e))?;

        if frame.header.key_frame() {
            if self.negotiation_possible(&frame)
                && matches!(self.negotiation_status, NegotiationStatus::Negotiated)
            {
                self.negotiation_status = NegotiationStatus::NonNegotiated;
            }
        }

        let queued_key_frame = match &mut self.negotiation_status {
            NegotiationStatus::NonNegotiated => {
                if frame.header.key_frame() {
                    self.backend.poll(BlockingMode::Blocking)?;

                    self.backend.new_sequence(&frame.header)?;

                    self.coded_resolution = Resolution {
                        width: u32::from(frame.header.width()),
                        height: u32::from(frame.header.height()),
                    };

                    self.negotiation_status = NegotiationStatus::Possible {
                        key_frame: (
                            timestamp,
                            Box::new(frame.header),
                            Vec::from(frame.bitstream.as_ref()),
                            Box::new(self.parser.clone()),
                        ),
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
            let (timestamp, header, bitstream, parser) = queued_key_frame;

            let bitstream = &bitstream as &dyn AsRef<[u8]>;

            let key_frame = Frame {
                bitstream,
                header: *header,
            };

            let mut handle = self.handle_frame(key_frame, timestamp, Some(*parser))?;

            if handle.picture().data.show_frame() {
                let order = self.current_display_order;

                handle.set_display_order(order);
                self.current_display_order += 1;

                self.ready_queue.push(handle);
            }

            self.negotiation_status = NegotiationStatus::Negotiated;
        }

        let mut handle = self.handle_frame(frame, timestamp, None)?;

        if self.backend.num_resources_left() == 0 {
            self.block_on_one()?;
        }

        self.backend.poll(self.blocking_mode)?;

        if handle.picture().data.show_frame() {
            let order = self.current_display_order;

            handle.set_display_order(order);
            self.current_display_order += 1;

            self.ready_queue.push(handle);
        }

        #[cfg(test)]
        self.steal_pics_for_test();

        let ready_frames = self.get_ready_frames();

        Ok(ready_frames
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }

    fn flush(&mut self) -> crate::decoders::Result<Vec<Box<dyn DynDecodedHandle>>> {
        // Decode whatever is pending using the default format. Mainly covers
        // the rare case where only one buffer is sent.
        if let NegotiationStatus::Possible { key_frame } = &self.negotiation_status {
            let (timestamp, header, bitstream, parser) = key_frame;

            let bitstream = &bitstream.clone() as &dyn AsRef<[u8]>;
            let header = header.as_ref().clone();

            let key_frame = Frame { bitstream, header };
            let timestamp = *timestamp;
            let parser = *parser.clone();

            self.handle_frame(key_frame, timestamp, Some(parser))?;
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

    fn backend(&self) -> &dyn crate::decoders::VideoDecoderBackend {
        self.backend.as_video_decoder_backend()
    }

    fn backend_mut(&mut self) -> &mut dyn crate::decoders::VideoDecoderBackend {
        self.backend.as_video_decoder_backend_mut()
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

    use crate::decoders::vp8::decoder::Decoder;
    use crate::decoders::vp8::parser::Header;
    use crate::decoders::BlockingMode;
    use crate::decoders::DecodedHandle;
    use crate::decoders::DynDecodedHandle;
    use crate::decoders::VideoDecoder;
    use crate::utils::dummy::Backend;

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
    fn test_25fps_vp8() {
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-25fps.vp8");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 250);
        }
    }
}

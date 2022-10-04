// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::convert::TryFrom;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use libva::BufferType;
use libva::IQMatrix;
use libva::IQMatrixBufferVP8;
use libva::Picture;
use libva::ProbabilityDataBufferVP8;
use vp8::parser as vp8;

use crate::virtio::video::decoder::backend::vaapi::BufferMapping;
use crate::virtio::video::decoder::backend::vaapi::DecodedFrameHandle;
use crate::virtio::video::decoder::backend::vaapi::DrcParams;
use crate::virtio::video::decoder::backend::vaapi::Resolution;
use crate::virtio::video::decoder::backend::vaapi::StreamMetadataState;
use crate::virtio::video::decoder::backend::vaapi::SurfacePoolHandle;
use crate::virtio::video::decoder::backend::vaapi::VaapiCodec;
use crate::virtio::video::decoder::backend::vaapi::VaapiDecoderSession;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::Rect;
use crate::virtio::video::resource::GuestResourceHandle;

/// The number of surfaces to allocate for this codec. Same as GStreamer's vavp8dec.
const NUM_SURFACES: usize = 7;

#[cfg(test)]
#[derive(Default)]
struct Params {
    pic_param: Option<BufferType>,
    slice_param: Option<BufferType>,
    slice_data: Option<BufferType>,
    iq_matrix: Option<BufferType>,
    probability_table: Option<BufferType>,
    last_pic: Option<DecodedFrameHandle>,
}

pub struct Vp8Codec {
    /// The metadata state. Updated whenever the decoder reads new data from the stream.
    metadata_state: StreamMetadataState,

    /// A parser to extract bitstream data and build frame data in turn
    parser: vp8::Parser,

    /// The picture used as the last reference picture.
    last_picture: Option<DecodedFrameHandle>,
    /// The picture used as the golden reference picture.
    golden_ref_picture: Option<DecodedFrameHandle>,
    /// The picture used as the alternate reference picture.
    alt_ref_picture: Option<DecodedFrameHandle>,

    /// The VAImageFormat we will decode into
    image_fmt: Option<libva::VAImageFormat>,
    /// The current resolution
    resolution: Resolution,

    /// Whether we are still waiting for the leading key frame. We skip all
    /// frames until then, since decoding can only start from key frames.
    wait_keyframe: bool,

    /// Whether the initial setup is done after reading some metadata for the
    /// first time.
    open: bool,

    /// Whether the codec has identified a dynamic resolution change. Cleared
    /// when this information is relayed to the session.
    drc: bool,

    #[cfg(test)]
    params: Params,
}

impl Vp8Codec {
    /// Create a new codec backend for VP8.
    pub fn new(display: Rc<libva::Display>) -> Result<Self> {
        Ok(Self {
            metadata_state: StreamMetadataState::Unparsed { display },
            parser: Default::default(),
            last_picture: Default::default(),
            golden_ref_picture: Default::default(),
            alt_ref_picture: Default::default(),
            image_fmt: Default::default(),
            resolution: Default::default(),
            wait_keyframe: true,
            open: Default::default(),
            drc: Default::default(),

            #[cfg(test)]
            params: Default::default(),
        })
    }

    /// A clamp such that min <= x <= max
    fn clamp<T: PartialOrd>(x: T, low: T, high: T) -> T {
        if x > high {
            high
        } else if x < low {
            low
        } else {
            x
        }
    }

    fn change_resolution(&mut self, resolution: Resolution) -> Result<()> {
        self.resolution = resolution;

        let mut pool = self.metadata_state.surface_pool()?;

        // Tell the pool so it can refuse stale surfaces.
        pool.set_current_resolution(resolution);

        self.drc = true;

        Ok(())
    }

    /// Initialize the codec state by reading some metadata from the current
    /// frame.
    fn open(&mut self, frame_hdr: &vp8::Header) -> Result<()> {
        let display = self.metadata_state.display();

        let va_profile = libva::VAProfile::VAProfileVP8Version0_3;
        let rt_format = libva::constants::VA_RT_FORMAT_YUV420;

        let frame_w = u32::from(frame_hdr.width());
        let frame_h = u32::from(frame_hdr.height());

        let attrs = vec![libva::VAConfigAttrib {
            type_: libva::VAConfigAttribType::VAConfigAttribRTFormat,
            value: rt_format,
        }];

        let config = display.create_config(
            Some(attrs),
            va_profile,
            libva::VAEntrypoint::VAEntrypointVLD,
        )?;

        let surfaces = VaapiDecoderSession::create_surfaces(
            Rc::clone(&display),
            frame_w,
            frame_h,
            rt_format,
            NUM_SURFACES,
        )?;

        let context = Rc::new(display.create_context(
            &config,
            i32::try_from(frame_w)?,
            i32::try_from(frame_h)?,
            Some(&surfaces),
            true,
        )?);

        let resolution = Resolution {
            width: frame_w,
            height: frame_h,
        };

        let surface_pool = SurfacePoolHandle::new(surfaces, resolution);

        self.metadata_state = StreamMetadataState::Parsed {
            context,
            config,
            surface_pool,
        };

        self.change_resolution(resolution)?;

        Ok(())
    }

    /// Check for new stream parameters. This might mean that the surfaces
    /// and/or context get recreated. If a new resolution is detected, the
    /// decoder will enter a DRC state and it will ask crosvm for new output
    /// buffers to write to.
    fn check_stream_params(&mut self, frame_hdr: &vp8::Header) -> Result<()> {
        let frame_w = u32::from(frame_hdr.width());
        let frame_h = u32::from(frame_hdr.height());

        assert!(frame_hdr.version() <= 3);

        let rt_format = libva::constants::VA_RT_FORMAT_YUV420;

        let recreate_surfaces =
            self.resolution.width != frame_w || self.resolution.height != frame_h;

        if recreate_surfaces {
            let display = self.metadata_state.display();
            let surfaces = VaapiDecoderSession::create_surfaces(
                display,
                frame_w,
                frame_h,
                rt_format,
                NUM_SURFACES,
            )?;

            let mut pool = self.metadata_state.surface_pool()?;

            // Drop the old surfaces still in the pool
            pool.drop_surfaces();

            for surface in surfaces {
                pool.add_surface(surface)
            }

            self.change_resolution(Resolution {
                width: frame_w,
                height: frame_h,
            })?;
        }

        Ok(())
    }

    fn build_iq_matrix(frame_hdr: &vp8::Header, parser: &vp8::Parser) -> Result<libva::BufferType> {
        let mut quantization_index: [[u16; 6]; 4] = Default::default();
        let seg = parser.segmentation();

        for (i, quantization_index) in quantization_index.iter_mut().enumerate() {
            let mut qi_base: i16;

            if seg.segmentation_enabled {
                qi_base = i16::from(seg.quantizer_update_value[i]);
                if !seg.segment_feature_mode {
                    qi_base += i16::from(frame_hdr.quant_indices().y_ac_qi);
                }
            } else {
                qi_base = i16::from(frame_hdr.quant_indices().y_ac_qi);
            }

            let mut qi = qi_base;
            quantization_index[0] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
            qi = qi_base + i16::from(frame_hdr.quant_indices().y_dc_delta);
            quantization_index[1] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_dc_delta);
            quantization_index[2] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_ac_delta);
            quantization_index[3] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_dc_delta);
            quantization_index[4] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_ac_delta);
            quantization_index[5] = Vp8Codec::clamp(u16::try_from(qi)?, 0, 127);
        }

        Ok(BufferType::IQMatrix(IQMatrix::VP8(IQMatrixBufferVP8::new(
            quantization_index,
        ))))
    }

    fn build_probability_table(frame_hdr: &vp8::Header) -> libva::BufferType {
        BufferType::Probability(ProbabilityDataBufferVP8::new(frame_hdr.coeff_prob()))
    }

    fn build_pic_param(
        frame_hdr: &vp8::Header,
        resolution: &Resolution,
        seg: &vp8::Segmentation,
        adj: &vp8::MbLfAdjustments,
        last: &Option<DecodedFrameHandle>,
        golden: &Option<DecodedFrameHandle>,
        alt: &Option<DecodedFrameHandle>,
    ) -> Result<libva::BufferType> {
        let mut loop_filter_level: [u8; 4] = Default::default();
        let mut loop_filter_deltas_ref_frame: [i8; 4] = Default::default();
        let mut loop_filter_deltas_mode: [i8; 4] = Default::default();

        for i in 0..4 {
            let mut level;
            if seg.segmentation_enabled {
                level = seg.lf_update_value[i];
                if !seg.segment_feature_mode {
                    level += i8::try_from(frame_hdr.loop_filter_level())?;
                }
            } else {
                level = i8::try_from(frame_hdr.loop_filter_level())?;
            }

            loop_filter_level[i] = Vp8Codec::clamp(u8::try_from(level)?, 0, 63);
            loop_filter_deltas_ref_frame[i] = adj.ref_frame_delta[i];
            loop_filter_deltas_mode[i] = adj.mb_mode_delta[i];
        }

        let last_surface = if let Some(last_ref) = last {
            last_ref.picture().borrow().surface().id()
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let golden_surface = if let Some(golden_ref) = golden {
            golden_ref.picture().borrow().surface().id()
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let alt_surface = if let Some(alt_ref) = alt {
            alt_ref.picture().borrow().surface().id()
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let pic_fields = libva::VP8PicFields::new(
            u32::from(!frame_hdr.key_frame()),
            u32::from(frame_hdr.version()),
            u32::from(seg.segmentation_enabled),
            u32::from(seg.update_mb_segmentation_map),
            u32::from(seg.update_segment_feature_data),
            u32::from(frame_hdr.filter_type()),
            u32::from(frame_hdr.sharpness_level()),
            u32::from(adj.loop_filter_adj_enable),
            u32::from(adj.mode_ref_lf_delta_update),
            u32::from(frame_hdr.sign_bias_golden()),
            u32::from(frame_hdr.sign_bias_alternate()),
            u32::from(frame_hdr.mb_no_coeff_skip()),
            u32::from(frame_hdr.loop_filter_level() == 0),
        );

        let bool_coder_ctx = libva::BoolCoderContextVPX::new(
            u8::try_from(frame_hdr.bd_range())?,
            u8::try_from(frame_hdr.bd_value())?,
            u8::try_from(frame_hdr.bd_count())?,
        );

        let pic_param = libva::PictureParameterBufferVP8::new(
            resolution.width,
            resolution.height,
            last_surface,
            golden_surface,
            alt_surface,
            &pic_fields,
            seg.segment_prob,
            loop_filter_level,
            loop_filter_deltas_ref_frame,
            loop_filter_deltas_mode,
            frame_hdr.prob_skip_false(),
            frame_hdr.prob_intra(),
            frame_hdr.prob_last(),
            frame_hdr.prob_golden(),
            frame_hdr.mode_probs().intra_16x16_prob,
            frame_hdr.mode_probs().intra_chroma_prob,
            frame_hdr.mv_prob(),
            &bool_coder_ctx,
        );

        Ok(libva::BufferType::PictureParameter(
            libva::PictureParameter::VP8(pic_param),
        ))
    }

    fn build_slice_param(frame_hdr: &vp8::Header, slice_size: usize) -> Result<libva::BufferType> {
        let mut partition_size: [u32; 9] = Default::default();
        let num_of_partitions = (1 << frame_hdr.log2_nbr_of_dct_partitions()) + 1;

        partition_size[0] = frame_hdr.first_part_size() - ((frame_hdr.header_size() + 7) >> 3);

        partition_size[1..num_of_partitions]
            .clone_from_slice(&frame_hdr.partition_size()[..(num_of_partitions - 1)]);

        Ok(libva::BufferType::SliceParameter(
            libva::SliceParameter::VP8(libva::SliceParameterBufferVP8::new(
                u32::try_from(slice_size)?,
                u32::from(frame_hdr.data_chunk_size()),
                0,
                frame_hdr.header_size(),
                u8::try_from(num_of_partitions)?,
                partition_size,
            )),
        ))
    }

    /// Replace a reference frame with `picture`.
    fn replace_reference(reference: &mut Option<DecodedFrameHandle>, picture: &DecodedFrameHandle) {
        *reference = Some(picture.clone());
    }

    fn update_references(
        decoded_frame: &DecodedFrameHandle,
        last_picture: &mut Option<DecodedFrameHandle>,
        golden_ref_picture: &mut Option<DecodedFrameHandle>,
        alt_ref_picture: &mut Option<DecodedFrameHandle>,
    ) -> Result<()> {
        let header = decoded_frame
            .header
            .downcast_ref::<vp8::Header>()
            .with_context(|| "decoded frame header is not a VP8 header")?;

        if header.key_frame() {
            Vp8Codec::replace_reference(last_picture, decoded_frame);
            Vp8Codec::replace_reference(golden_ref_picture, decoded_frame);
            Vp8Codec::replace_reference(alt_ref_picture, decoded_frame);
        } else {
            if header.refresh_alternate_frame() {
                Vp8Codec::replace_reference(alt_ref_picture, decoded_frame);
            } else {
                match header.copy_buffer_to_alternate() {
                    0 => { /* do nothing */ }

                    1 => {
                        if let Some(last_picture) = last_picture {
                            Vp8Codec::replace_reference(alt_ref_picture, last_picture);
                        }
                    }

                    2 => {
                        if let Some(golden_ref) = golden_ref_picture {
                            Vp8Codec::replace_reference(alt_ref_picture, golden_ref);
                        }
                    }

                    other => panic!("Invalid value: {}", other),
                }
            }

            if header.refresh_golden_frame() {
                Vp8Codec::replace_reference(golden_ref_picture, decoded_frame);
            } else {
                match header.copy_buffer_to_golden() {
                    0 => { /* do nothing */ }

                    1 => {
                        if let Some(last_picture) = last_picture {
                            Vp8Codec::replace_reference(golden_ref_picture, last_picture);
                        }
                    }

                    2 => {
                        if let Some(alt_ref) = alt_ref_picture {
                            Vp8Codec::replace_reference(golden_ref_picture, alt_ref);
                        }
                    }

                    other => panic!("Invalid value: {}", other),
                }
            }

            if header.refresh_last() {
                Vp8Codec::replace_reference(last_picture, decoded_frame);
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn save_params(
        params: &mut Params,
        pic_param: BufferType,
        slice_param: BufferType,
        slice_data: BufferType,
        iq_matrix: BufferType,
        probability_table: BufferType,
        last_pic: DecodedFrameHandle,
    ) {
        params.pic_param = Some(pic_param);
        params.slice_param = Some(slice_param);
        params.slice_data = Some(slice_data);
        params.iq_matrix = Some(iq_matrix);
        params.probability_table = Some(probability_table);
        params.last_pic = Some(last_pic);
    }

    /// Decode a single frame, copying the decoded data into the output buffer
    /// as per the format in `self.image_fmt`.
    fn decode_frame<T: AsRef<[u8]>>(
        &mut self,
        frame: vp8::Frame<T>,
        timestamp: u64,
    ) -> Result<DecodedFrameHandle> {
        let context = self.metadata_state.context()?;

        let iq_buffer =
            context.create_buffer(Vp8Codec::build_iq_matrix(&frame.header, &self.parser)?)?;
        let probs = context.create_buffer(Vp8Codec::build_probability_table(&frame.header))?;

        let pic_param = context.create_buffer(Vp8Codec::build_pic_param(
            &frame.header,
            &self.resolution,
            self.parser.segmentation(),
            self.parser.mb_lf_adjust(),
            &self.last_picture,
            &self.golden_ref_picture,
            &self.alt_ref_picture,
        )?)?;

        let slice_param = context.create_buffer(Vp8Codec::build_slice_param(
            &frame.header,
            frame.bitstream.as_ref().len(),
        )?)?;
        let slice_data = context.create_buffer(libva::BufferType::SliceData(Vec::from(
            frame.bitstream.as_ref(),
        )))?;

        let context = self.metadata_state.context()?;
        let surface = self.metadata_state.get_surface()?;

        let mut picture = Picture::new(timestamp, Rc::clone(&context), surface);

        // Add buffers with the parsed data.
        picture.add_buffer(iq_buffer);
        picture.add_buffer(probs);
        picture.add_buffer(pic_param);
        picture.add_buffer(slice_param);
        picture.add_buffer(slice_data);

        let picture = picture.begin()?.render()?.end()?.sync()?;
        let picture = Rc::new(RefCell::new(picture));

        #[cfg(test)]
        Vp8Codec::save_params(
            &mut self.params,
            Vp8Codec::build_pic_param(
                &frame.header,
                &self.resolution,
                self.parser.segmentation(),
                self.parser.mb_lf_adjust(),
                &self.last_picture,
                &self.golden_ref_picture,
                &self.alt_ref_picture,
            )?,
            Vp8Codec::build_slice_param(&frame.header, frame.bitstream.as_ref().len())?,
            libva::BufferType::SliceData(Vec::from(frame.bitstream.as_ref())),
            Vp8Codec::build_iq_matrix(&frame.header, &self.parser)?,
            Vp8Codec::build_probability_table(&frame.header),
            DecodedFrameHandle::new(
                Rc::clone(&picture),
                Rc::new(frame.header.clone()),
                self.resolution,
                self.metadata_state.surface_pool()?,
            ),
        );

        let decoded_frame = DecodedFrameHandle::new(
            picture,
            Rc::new(frame.header),
            self.resolution,
            self.metadata_state.surface_pool()?,
        );

        // Do DPB management
        Vp8Codec::update_references(
            &decoded_frame,
            &mut self.last_picture,
            &mut self.golden_ref_picture,
            &mut self.alt_ref_picture,
        )?;

        Ok(decoded_frame)
    }

    /// Handle a single frame.
    fn handle_frame<T: AsRef<[u8]>>(
        &mut self,
        frame: vp8::Frame<T>,
        timestamp: u64,
    ) -> Result<Vec<DecodedFrameHandle>> {
        if self.wait_keyframe {
            if !frame.header.key_frame() {
                return Ok(Vec::new());
            }
        }

        if !self.open {
            self.open(&frame.header)?;
            self.open = true;
        }

        self.wait_keyframe = false;

        if frame.header.key_frame() {
            // Always check for changes at every key frame
            self.check_stream_params(&frame.header)?;
        }

        Ok(vec![(self.decode_frame(frame, timestamp)?)])
    }
}

impl VaapiCodec for Vp8Codec {
    fn decode(
        &mut self,
        timestamp: u64,
        resource: &GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> Result<Vec<DecodedFrameHandle>> {
        let bytes_used =
            usize::try_from(bytes_used).map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        let offset = usize::try_from(offset).map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        let bitstream_map: BufferMapping<_, GuestResourceHandle> =
            BufferMapping::new(resource, offset, bytes_used)?;
        let frame = self
            .parser
            .parse_frame(bitstream_map.as_ref())
            .map_err(|e| VideoError::BackendFailure(anyhow!(e)))?;

        self.handle_frame(frame, timestamp)
    }

    fn flush(&mut self) -> Result<Vec<DecodedFrameHandle>> {
        self.wait_keyframe = true;

        // VP8 has no internal picture queue, so simply return nothing here.
        Ok(vec![])
    }

    fn va_image_fmt(&self) -> &Option<libva::VAImageFormat> {
        &self.image_fmt
    }

    fn set_raw_fmt(&mut self, format: Format) -> Result<()> {
        let image_formats = self.metadata_state.display().query_image_formats()?;

        //TODO: this is hardcoded to NV12 for now. Will change when a proper
        //Format is implemented in the libva crate so we can use TryFrom.
        let image_fmt = image_formats
            .into_iter()
            .find(|f| f.fourcc == libva::constants::VA_FOURCC_NV12)
            .with_context(|| format!("unsupported format {}", format))?;

        self.image_fmt = Some(image_fmt);

        Ok(())
    }

    fn drc(&mut self) -> Option<DrcParams> {
        if self.drc {
            self.drc = false;

            Some(DrcParams {
                min_num_buffers: NUM_SURFACES,
                width: self.resolution.width,
                height: self.resolution.height,
                visible_rect: Rect {
                    left: 0,
                    top: 0,
                    right: self.resolution.width as i32,
                    bottom: self.resolution.height as i32,
                },
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::io::Read;
    use std::io::Seek;

    use base::FromRawDescriptor;
    use base::SafeDescriptor;
    use base::SharedMemory;
    use bytes::Buf;
    use libva::BufferType;
    use libva::IQMatrix;
    use libva::PictureParameter;
    use libva::SliceParameter;

    use crate::virtio::video::decoder::backend::vaapi::tests::build_resource;
    use crate::virtio::video::decoder::backend::vaapi::vp8::Vp8Codec;
    use crate::virtio::video::decoder::backend::vaapi::vp8::NUM_SURFACES;
    use crate::virtio::video::decoder::backend::vaapi::VaapiDecoder;
    use crate::virtio::video::decoder::backend::vaapi::VaapiDecoderSession;
    use crate::virtio::video::decoder::backend::DecoderBackend;
    use crate::virtio::video::decoder::backend::DecoderEvent;
    use crate::virtio::video::decoder::backend::DecoderSession;
    use crate::virtio::video::format::Format;
    use crate::virtio::video::format::FramePlane;
    use crate::virtio::video::format::Rect;
    use crate::virtio::video::resource::GuestMemArea;
    use crate::virtio::video::resource::GuestMemHandle;
    use crate::virtio::video::resource::GuestResource;
    use crate::virtio::video::resource::GuestResourceHandle;

    fn get_codec(session: &mut VaapiDecoderSession) -> &mut Vp8Codec {
        session.codec.as_mut().downcast_mut::<Vp8Codec>().unwrap()
    }

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

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_vp8() {
        // Test video stream and its properties. Compare the parameters for frames
        // 0,1, 2, and make sure the rest does not fail by unwraping the result
        // of codec.handle_frame()
        const TEST_25_FPS_VP8_STREAM: &[u8] = include_bytes!("test-25fps.vp8");
        const TEST_25_FPS_VP8_STREAM_WIDTH: i32 = 320;
        const TEST_25_FPS_VP8_STREAM_HEIGHT: i32 = 240;
        const NUM_BUFS: u32 = NUM_SURFACES as u32;

        // Extracted using "LIBVA_TRACE=libva LIBVA_TRACE_BUFDATA=1 gst-launch-1.0
        // filesrc location=test-25fps.vp8 ! parsebin ! vavp8dec ! fakevideosink"
        // A couple frames worth of data should make it easier spot parser/decoder
        // issues in contrast with using only a crc check
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("test-25fps-vp8-slice-data-0.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("test-25fps-vp8-slice-data-1.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("test-25fps-vp8-slice-data-2.bin");

        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_0: &[u8] =
            include_bytes!("test-25fps-vp8-probability-table-0.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_1: &[u8] =
            include_bytes!("test-25fps-vp8-probability-table-1.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_2: &[u8] =
            include_bytes!("test-25fps-vp8-probability-table-2.bin");

        const VP8_STREAM_CRCS: &str = include_str!("test-25fps.vp8.crc");
        let mut expected_frames_crcs = VP8_STREAM_CRCS.lines();

        let mut cursor = Cursor::new(TEST_25_FPS_VP8_STREAM);
        // Confirm the width and height of the stream.
        cursor.seek(std::io::SeekFrom::Start(12)).unwrap();
        let w = cursor.get_u16_le();
        let h = cursor.get_u16_le();
        assert!(w as i32 == TEST_25_FPS_VP8_STREAM_WIDTH);
        assert!(h as i32 == TEST_25_FPS_VP8_STREAM_HEIGHT);

        // Skip the IVH header entirely.
        cursor.seek(std::io::SeekFrom::Start(32)).unwrap();

        let mut decoder = VaapiDecoder::new().unwrap();
        let mut session = decoder.new_session(Format::VP8).unwrap();

        // Output buffers suitable for receiving NV12 frames for our stream.
        let output_buffers = (0..NUM_BUFS)
            .into_iter()
            .map(|_| {
                SharedMemory::new(
                    "",
                    (TEST_25_FPS_VP8_STREAM_WIDTH * TEST_25_FPS_VP8_STREAM_HEIGHT * 3 / 2) as u64,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut frame_num = 0;
        while let Some(packet) = read_ivf_packet(&mut cursor) {
            session
                .decode(
                    0,
                    frame_num as u64,
                    build_resource(packet.as_ref()),
                    0,
                    packet.len() as u32,
                )
                .unwrap();

            // After sending the first buffer we should get the initial
            // resolution change event and can provide the frames to decode
            // into.
            if frame_num == 0 {
                assert!(session.event_queue.len() == 2);

                // Done with input buffer 0 and Waiting for output buffers.
                assert!(matches!(
                    session.read_event().unwrap(),
                    DecoderEvent::ProvidePictureBuffers {
                        min_num_buffers: NUM_BUFS,
                        width: TEST_25_FPS_VP8_STREAM_WIDTH,
                        height: TEST_25_FPS_VP8_STREAM_HEIGHT,
                        visible_rect: Rect {
                            left: 0,
                            top: 0,
                            right: TEST_25_FPS_VP8_STREAM_WIDTH,
                            bottom: TEST_25_FPS_VP8_STREAM_HEIGHT,
                        },
                    } | DecoderEvent::NotifyEndOfBitstreamBuffer(0)
                ));

                assert!(matches!(
                    session.read_event().unwrap(),
                    DecoderEvent::ProvidePictureBuffers {
                        min_num_buffers: NUM_BUFS,
                        width: TEST_25_FPS_VP8_STREAM_WIDTH,
                        height: TEST_25_FPS_VP8_STREAM_HEIGHT,
                        visible_rect: Rect {
                            left: 0,
                            top: 0,
                            right: TEST_25_FPS_VP8_STREAM_WIDTH,
                            bottom: TEST_25_FPS_VP8_STREAM_HEIGHT,
                        },
                    } | DecoderEvent::NotifyEndOfBitstreamBuffer(0)
                ));

                session
                    .set_output_parameters(NUM_BUFS as usize, Format::NV12)
                    .unwrap();

                // Pass the buffers we will decode into.
                for (picture_buffer_id, buffer) in output_buffers.iter().enumerate() {
                    let handle = GuestResourceHandle::GuestPages(GuestMemHandle {
                        // Safe because we are taking ownership of a just-duplicated FD.
                        desc: unsafe {
                            SafeDescriptor::from_raw_descriptor(
                                base::clone_descriptor(buffer).unwrap(),
                            )
                        },
                        mem_areas: vec![GuestMemArea {
                            offset: 0,
                            length: buffer.size() as usize,
                        }],
                    });

                    session
                        .use_output_buffer(
                            picture_buffer_id as i32,
                            GuestResource {
                                handle,
                                planes: vec![
                                    FramePlane {
                                        offset: 0,
                                        stride: TEST_25_FPS_VP8_STREAM_WIDTH as usize,
                                        size: (TEST_25_FPS_VP8_STREAM_WIDTH
                                            * TEST_25_FPS_VP8_STREAM_HEIGHT)
                                            as usize,
                                    },
                                    FramePlane {
                                        offset: (TEST_25_FPS_VP8_STREAM_WIDTH
                                            * TEST_25_FPS_VP8_STREAM_HEIGHT)
                                            as usize,
                                        stride: TEST_25_FPS_VP8_STREAM_WIDTH as usize,
                                        size: (TEST_25_FPS_VP8_STREAM_WIDTH
                                            * TEST_25_FPS_VP8_STREAM_HEIGHT
                                            / 2)
                                            as usize,
                                    },
                                ],
                                width: TEST_25_FPS_VP8_STREAM_WIDTH as u32,
                                height: TEST_25_FPS_VP8_STREAM_HEIGHT as u32,
                                format: Format::NV12,
                            },
                        )
                        .unwrap();
                }
            }

            let codec = get_codec(&mut session);
            let params = &codec.params;
            let pic_param = match params.pic_param {
                Some(BufferType::PictureParameter(PictureParameter::VP8(ref pic_param))) => {
                    pic_param
                }
                _ => panic!(),
            };

            let slice_param = match params.slice_param {
                Some(BufferType::SliceParameter(SliceParameter::VP8(ref slice_param))) => {
                    slice_param
                }
                _ => panic!(),
            };

            let slice_data = match params.slice_data {
                Some(BufferType::SliceData(ref data)) => data,
                _ => panic!(),
            };

            let iq_matrix = match params.iq_matrix {
                Some(BufferType::IQMatrix(IQMatrix::VP8(ref iq_matrix))) => iq_matrix,
                _ => panic!(),
            };

            let probability_table = match params.probability_table {
                Some(BufferType::Probability(ref probability_table)) => probability_table,
                _ => panic!(),
            };

            let last_pic = params.last_pic.as_ref().unwrap();

            // Uncomment to dump the YUV output to /tmp
            // VaapiDecoderSession::get_test_nv12(
            //     codec.metadata_state.display(),
            //     last_pic.picture(),
            //     320,
            //     240,
            //     |nv12| {
            //         std::fs::write(
            //             format!("/tmp/{}_frame{}.yuv", "test_25fps.vp8", frame_num),
            //             nv12,
            //         )
            //         .unwrap();
            //     },
            // );

            let frame_crc = VaapiDecoderSession::get_test_nv12(
                codec.metadata_state.display(),
                last_pic.picture(),
                320,
                240,
                crc32fast::hash,
            );
            assert_eq!(
                format!("{:08x}", frame_crc),
                expected_frames_crcs
                    .next()
                    .expect("No CRC for decoded frame")
            );

            if frame_num == 0 {
                assert_eq!(iq_matrix.inner().quantization_index, [[4; 6]; 4]);
                for i in 0..4 {
                    for j in 0..8 {
                        for k in 0..3 {
                            for l in 0..11 {
                                const OFF_I: usize = 8 * 3 * 11;
                                const OFF_J: usize = 3 * 11;
                                const OFF_K: usize = 11;
                                // maybe std::transmute?
                                assert_eq!(
                                    probability_table.inner().dct_coeff_probs[i][j][k][l],
                                    TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_0
                                        [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                );
                            }
                        }
                    }
                }

                assert_eq!(pic_param.inner().frame_width, 320);
                assert_eq!(pic_param.inner().frame_height, 240);
                assert_eq!(
                    pic_param.inner().last_ref_frame,
                    libva::constants::VA_INVALID_SURFACE
                );
                assert_eq!(
                    pic_param.inner().golden_ref_frame,
                    libva::constants::VA_INVALID_SURFACE
                );
                assert_eq!(
                    pic_param.inner().alt_ref_frame,
                    libva::constants::VA_INVALID_SURFACE
                );
                assert_eq!(
                    pic_param.inner().out_of_loop_frame,
                    libva::constants::VA_INVALID_SURFACE
                );

                // Safe because this bitfield is initialized by the decoder.
                assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                    libva::VP8PicFields::new(0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1)
                        .inner()
                        .value
                });

                assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                assert_eq!(pic_param.inner().loop_filter_level, [0; 4]);
                assert_eq!(
                    pic_param.inner().loop_filter_deltas_ref_frame,
                    [2, 0, -2, -2]
                );
                assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                assert_eq!(pic_param.inner().prob_skip_false, 0xbe);
                assert_eq!(pic_param.inner().prob_intra, 0);
                assert_eq!(pic_param.inner().prob_last, 0);
                assert_eq!(pic_param.inner().prob_gf, 0);

                assert_eq!(pic_param.inner().y_mode_probs, [0x91, 0x9c, 0xa3, 0x80]);
                assert_eq!(pic_param.inner().uv_mode_probs, [0x8e, 0x72, 0xb7]);
                assert_eq!(
                    pic_param.inner().mv_probs[0],
                    [
                        0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81, 0x84,
                        0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe
                    ]
                );
                assert_eq!(
                    pic_param.inner().mv_probs[1],
                    [
                        0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82, 0x82,
                        0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                    ]
                );

                assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xfc);
                assert_eq!(pic_param.inner().bool_coder_ctx.value, 0x39);
                assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x0);

                assert_eq!(
                    slice_param.inner(),
                    libva::SliceParameterBufferVP8::new(
                        14788,
                        10,
                        0,
                        3040,
                        2,
                        [926, 13472, 0, 0, 0, 0, 0, 0, 0],
                    )
                    .inner(),
                );

                assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_0);
            } else if frame_num == 1 {
                assert_eq!(iq_matrix.inner().quantization_index, [[0x7f; 6]; 4]);
                for i in 0..4 {
                    for j in 0..8 {
                        for k in 0..3 {
                            for l in 0..11 {
                                const OFF_I: usize = 8 * 3 * 11;
                                const OFF_J: usize = 3 * 11;
                                const OFF_K: usize = 11;
                                // maybe std::transmute?
                                assert_eq!(
                                    probability_table.inner().dct_coeff_probs[i][j][k][l],
                                    TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_1
                                        [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                );
                            }
                        }
                    }
                }
                assert_eq!(pic_param.inner().frame_width, 320);
                assert_eq!(pic_param.inner().frame_height, 240);
                assert_eq!(pic_param.inner().last_ref_frame, 0);
                assert_eq!(pic_param.inner().golden_ref_frame, 0);
                assert_eq!(pic_param.inner().alt_ref_frame, 0);
                assert_eq!(
                    pic_param.inner().out_of_loop_frame,
                    libva::constants::VA_INVALID_SURFACE
                );

                // Safe because this bitfield is initialized by the decoder.
                assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                    libva::VP8PicFields::new(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0)
                        .inner()
                        .value
                });

                assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                assert_eq!(pic_param.inner().loop_filter_level, [44; 4]);
                assert_eq!(
                    pic_param.inner().loop_filter_deltas_ref_frame,
                    [2, 0, -2, -2]
                );
                assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                assert_eq!(pic_param.inner().prob_skip_false, 0x11);
                assert_eq!(pic_param.inner().prob_intra, 0x2a);
                assert_eq!(pic_param.inner().prob_last, 0xff);
                assert_eq!(pic_param.inner().prob_gf, 0x80);

                assert_eq!(pic_param.inner().y_mode_probs, [0x70, 0x56, 0x8c, 0x25]);
                assert_eq!(pic_param.inner().uv_mode_probs, [0xa2, 0x65, 0xcc]);
                assert_eq!(
                    pic_param.inner().mv_probs[0],
                    [
                        0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81, 0x84,
                        0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                    ]
                );
                assert_eq!(
                    pic_param.inner().mv_probs[1],
                    [
                        0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82, 0x82,
                        0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                    ]
                );

                assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xde);
                assert_eq!(pic_param.inner().bool_coder_ctx.value, 0x39);
                assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x7);

                assert_eq!(
                    slice_param.inner(),
                    libva::SliceParameterBufferVP8::new(
                        257,
                        3,
                        0,
                        129,
                        2,
                        [143, 94, 0, 0, 0, 0, 0, 0, 0],
                    )
                    .inner()
                );

                assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_1);
            } else if frame_num == 2 {
                assert_eq!(iq_matrix.inner().quantization_index, [[0x7f; 6]; 4]);
                for i in 0..4 {
                    for j in 0..8 {
                        for k in 0..3 {
                            for l in 0..11 {
                                const OFF_I: usize = 8 * 3 * 11;
                                const OFF_J: usize = 3 * 11;
                                const OFF_K: usize = 11;
                                // maybe std::transmute?
                                assert_eq!(
                                    probability_table.inner().dct_coeff_probs[i][j][k][l],
                                    TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_2
                                        [(i * OFF_I) + (j * OFF_J) + (k * OFF_K) + l]
                                );
                            }
                        }
                    }
                }
                assert_eq!(pic_param.inner().frame_width, 320);
                assert_eq!(pic_param.inner().frame_height, 240);
                assert_eq!(pic_param.inner().last_ref_frame, 1);
                assert_eq!(pic_param.inner().golden_ref_frame, 0);
                assert_eq!(pic_param.inner().alt_ref_frame, 0);
                assert_eq!(
                    pic_param.inner().out_of_loop_frame,
                    libva::constants::VA_INVALID_SURFACE
                );

                // Safe because this bitfield is initialized by the decoder.
                assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                    libva::VP8PicFields::new(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0)
                        .inner()
                        .value
                });

                assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 3]);
                assert_eq!(pic_param.inner().loop_filter_level, [28; 4]);
                assert_eq!(
                    pic_param.inner().loop_filter_deltas_ref_frame,
                    [2, 0, -2, -2]
                );
                assert_eq!(pic_param.inner().loop_filter_deltas_mode, [4, -2, 2, 4]);
                assert_eq!(pic_param.inner().prob_skip_false, 0x6);
                assert_eq!(pic_param.inner().prob_intra, 0x1);
                assert_eq!(pic_param.inner().prob_last, 0xf8);
                assert_eq!(pic_param.inner().prob_gf, 0xff);

                assert_eq!(pic_param.inner().y_mode_probs, [0x70, 0x56, 0x8c, 0x25]);
                assert_eq!(pic_param.inner().uv_mode_probs, [0xa2, 0x65, 0xcc]);
                assert_eq!(
                    pic_param.inner().mv_probs[0],
                    [
                        0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81, 0x84,
                        0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                    ]
                );
                assert_eq!(
                    pic_param.inner().mv_probs[1],
                    [
                        0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82, 0x82,
                        0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
                    ]
                );

                assert_eq!(pic_param.inner().bool_coder_ctx.range, 0xb1);
                assert_eq!(pic_param.inner().bool_coder_ctx.value, 0xd);
                assert_eq!(pic_param.inner().bool_coder_ctx.count, 0x2);

                assert_eq!(
                    slice_param.inner(),
                    libva::SliceParameterBufferVP8::new(
                        131,
                        3,
                        0,
                        86,
                        2,
                        [66, 51, 0, 0, 0, 0, 0, 0, 0],
                    )
                    .inner()
                );

                assert_eq!(&slice_data[..], TEST_25_FPS_VP8_STREAM_SLICE_DATA_2);
            }

            // Assume for the purposes of this test that the output buffer can
            // be reused, otherwise we are going to run out
            let _ = session.reuse_output_buffer(frame_num as i32 % NUM_BUFS as i32);
            frame_num += 1;
        }
    }
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(test)]
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use libva::BufferType;
use libva::Display;
use libva::IQMatrix;
use libva::IQMatrixBufferVP8;
use libva::Picture as VaPicture;
use libva::ProbabilityDataBufferVP8;

use crate::decoders::vp8::backends::Result as StatelessBackendResult;
use crate::decoders::vp8::backends::StatelessDecoderBackend;
use crate::decoders::vp8::decoder::Decoder;
use crate::decoders::vp8::parser::Header;
use crate::decoders::vp8::parser::MbLfAdjustments;
use crate::decoders::vp8::parser::Segmentation;
use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::Result as DecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::VideoDecoderBackend;
use crate::utils::vaapi::DecodedHandle as VADecodedHandle;
use crate::utils::vaapi::GenericBackendHandle;
use crate::utils::vaapi::NegotiationStatus;
use crate::utils::vaapi::PendingJob;
use crate::utils::vaapi::StreamInfo;
use crate::utils::vaapi::VaapiBackend;
use crate::Resolution;

/// Resolves to the type used as Handle by the backend.
type AssociatedHandle = <Backend as VideoDecoderBackend>::Handle;

/// The number of surfaces to allocate for this codec. Same as GStreamer's vavp8dec.
const NUM_SURFACES: usize = 7;

#[cfg(test)]
struct TestParams {
    pic_param: BufferType,
    slice_param: BufferType,
    slice_data: BufferType,
    iq_matrix: BufferType,
    probability_table: BufferType,
}

impl StreamInfo for &Header {
    fn va_profile(&self) -> anyhow::Result<i32> {
        Ok(libva::VAProfile::VAProfileVP8Version0_3)
    }

    fn rt_format(&self) -> anyhow::Result<u32> {
        Ok(libva::constants::VA_RT_FORMAT_YUV420)
    }

    fn min_num_surfaces(&self) -> usize {
        NUM_SURFACES
    }

    fn coded_size(&self) -> (u32, u32) {
        (self.width() as u32, self.height() as u32)
    }

    fn visible_rect(&self) -> ((u32, u32), (u32, u32)) {
        ((0, 0), self.coded_size())
    }
}

struct Backend {
    backend: VaapiBackend<Header>,

    #[cfg(test)]
    /// Test params. Saves the metadata sent to VA-API for the purposes of
    /// testing.
    test_params: Vec<TestParams>,
}

impl Backend {
    /// Create a new codec backend for VP8.
    fn new(display: Rc<libva::Display>) -> Result<Self> {
        Ok(Self {
            backend: VaapiBackend::new(display),
            #[cfg(test)]
            test_params: Default::default(),
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

    /// Gets the VASurfaceID for the given `picture`.
    fn surface_id(picture: &GenericBackendHandle) -> libva::VASurfaceID {
        picture.surface_id()
    }

    fn build_iq_matrix(
        frame_hdr: &Header,
        segmentation: &Segmentation,
    ) -> Result<libva::BufferType> {
        let mut quantization_index: [[u16; 6]; 4] = Default::default();

        for (i, quantization_index) in quantization_index.iter_mut().enumerate() {
            let mut qi_base: i16;

            if segmentation.segmentation_enabled {
                qi_base = i16::from(segmentation.quantizer_update_value[i]);
                if !segmentation.segment_feature_mode {
                    qi_base += i16::from(frame_hdr.quant_indices().y_ac_qi);
                }
            } else {
                qi_base = i16::from(frame_hdr.quant_indices().y_ac_qi);
            }

            let mut qi = qi_base;
            quantization_index[0] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y_dc_delta);
            quantization_index[1] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_dc_delta);
            quantization_index[2] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().y2_ac_delta);
            quantization_index[3] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_dc_delta);
            quantization_index[4] = u16::try_from(Backend::clamp(qi, 0, 127))?;
            qi = qi_base + i16::from(frame_hdr.quant_indices().uv_ac_delta);
            quantization_index[5] = u16::try_from(Backend::clamp(qi, 0, 127))?;
        }

        Ok(BufferType::IQMatrix(IQMatrix::VP8(IQMatrixBufferVP8::new(
            quantization_index,
        ))))
    }

    fn build_probability_table(frame_hdr: &Header) -> libva::BufferType {
        BufferType::Probability(ProbabilityDataBufferVP8::new(frame_hdr.coeff_prob()))
    }

    fn build_pic_param(
        frame_hdr: &Header,
        resolution: &Resolution,
        seg: &Segmentation,
        adj: &MbLfAdjustments,
        last: Option<&AssociatedHandle>,
        golden: Option<&AssociatedHandle>,
        alt: Option<&AssociatedHandle>,
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

            loop_filter_level[i] = Backend::clamp(u8::try_from(level)?, 0, 63);
            loop_filter_deltas_ref_frame[i] = adj.ref_frame_delta[i];
            loop_filter_deltas_mode[i] = adj.mb_mode_delta[i];
        }

        let last_surface = if let Some(last_ref) = last {
            Self::surface_id(&last_ref.handle())
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let golden_surface = if let Some(golden_ref) = golden {
            Self::surface_id(&golden_ref.handle())
        } else {
            libva::constants::VA_INVALID_SURFACE
        };

        let alt_surface = if let Some(alt_ref) = alt {
            Self::surface_id(&alt_ref.handle())
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

    fn build_slice_param(frame_hdr: &Header, slice_size: usize) -> Result<libva::BufferType> {
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

    #[cfg(test)]
    fn save_params(
        &mut self,
        pic_param: BufferType,
        slice_param: BufferType,
        slice_data: BufferType,
        iq_matrix: BufferType,
        probability_table: BufferType,
    ) {
        let test_params = TestParams {
            pic_param,
            slice_param,
            slice_data,
            iq_matrix,
            probability_table,
        };

        self.test_params.push(test_params);
    }
}

impl StatelessDecoderBackend for Backend {
    fn new_sequence(&mut self, header: &Header) -> StatelessBackendResult<()> {
        self.backend.metadata_state.open(header, None)?;
        self.backend.negotiation_status = NegotiationStatus::Possible(Box::new(header.clone()));

        Ok(())
    }

    fn submit_picture(
        &mut self,
        picture: &Header,
        last_ref: Option<&Self::Handle>,
        golden_ref: Option<&Self::Handle>,
        alt_ref: Option<&Self::Handle>,
        bitstream: &[u8],
        segmentation: &Segmentation,
        mb_lf_adjust: &MbLfAdjustments,
        timestamp: u64,
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        self.backend.negotiation_status = NegotiationStatus::Negotiated;

        let context = self.backend.metadata_state.context()?;

        let iq_buffer = context.create_buffer(Backend::build_iq_matrix(picture, segmentation)?)?;

        let probs = context.create_buffer(Backend::build_probability_table(picture))?;

        let coded_resolution = self.backend.metadata_state.coded_resolution()?;

        let pic_param = context.create_buffer(Backend::build_pic_param(
            picture,
            &coded_resolution,
            segmentation,
            mb_lf_adjust,
            last_ref,
            golden_ref,
            alt_ref,
        )?)?;

        let slice_param =
            context.create_buffer(Backend::build_slice_param(picture, bitstream.len())?)?;

        let slice_data =
            context.create_buffer(libva::BufferType::SliceData(Vec::from(bitstream)))?;

        let context = self.backend.metadata_state.context()?;

        let surface = self
            .backend
            .metadata_state
            .get_surface()?
            .ok_or(StatelessBackendError::OutOfResources)?;

        let surface_id = surface.id();

        let mut va_picture = VaPicture::new(timestamp, Rc::clone(&context), surface);

        // Add buffers with the parsed data.
        va_picture.add_buffer(iq_buffer);
        va_picture.add_buffer(probs);
        va_picture.add_buffer(pic_param);
        va_picture.add_buffer(slice_param);
        va_picture.add_buffer(slice_data);

        let va_picture = va_picture.begin()?.render()?.end()?;

        #[cfg(test)]
        self.save_params(
            Backend::build_pic_param(
                picture,
                &coded_resolution,
                segmentation,
                mb_lf_adjust,
                last_ref,
                golden_ref,
                alt_ref,
            )?,
            Backend::build_slice_param(picture, bitstream.len())?,
            libva::BufferType::SliceData(Vec::from(bitstream)),
            Backend::build_iq_matrix(picture, segmentation)?,
            Backend::build_probability_table(picture),
        );

        let backend_handle = if block {
            let va_picture = va_picture.sync()?;
            let map_format = self.backend.metadata_state.map_format()?;

            Rc::new(RefCell::new(GenericBackendHandle::new_ready(
                va_picture,
                Rc::clone(map_format),
                self.backend.metadata_state.display_resolution()?,
            )))
        } else {
            let backend_handle =
                Rc::new(RefCell::new(GenericBackendHandle::new_pending(surface_id)));

            self.backend.pending_jobs.push_back(PendingJob {
                va_picture,
                codec_picture: Rc::clone(&backend_handle),
            });

            backend_handle
        };

        self.backend
            .build_va_decoded_handle(&backend_handle, timestamp)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
    }

    #[cfg(test)]
    fn get_test_params(&self) -> &dyn Any {
        &self.test_params
    }
}

impl VideoDecoderBackend for Backend {
    type Handle = VADecodedHandle;

    fn coded_resolution(&self) -> Option<Resolution> {
        self.backend.coded_resolution()
    }

    fn display_resolution(&self) -> Option<Resolution> {
        self.backend.display_resolution()
    }

    fn num_resources_total(&self) -> usize {
        self.backend.num_resources_total()
    }

    fn num_resources_left(&self) -> usize {
        self.backend.num_resources_left()
    }

    fn format(&self) -> Option<crate::DecodedFormat> {
        self.backend.format()
    }

    fn try_format(&mut self, format: crate::DecodedFormat) -> DecoderResult<()> {
        self.backend.try_format(format)
    }

    fn poll(&mut self, blocking_mode: BlockingMode) -> DecoderResult<VecDeque<Self::Handle>> {
        self.backend.poll(blocking_mode)
    }

    fn handle_is_ready(&self, handle: &Self::Handle) -> bool {
        self.backend.handle_is_ready(handle)
    }

    fn block_on_handle(&mut self, handle: &Self::Handle) -> StatelessBackendResult<()> {
        self.backend.block_on_handle(handle)
    }
}

impl Decoder<VADecodedHandle> {
    // Creates a new instance of the decoder using the VAAPI backend.
    pub fn new_vaapi(display: Rc<Display>, blocking_mode: BlockingMode) -> Result<Self> {
        Self::new(Box::new(Backend::new(display)?), blocking_mode)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use libva::BufferType;
    use libva::Display;
    use libva::IQMatrix;
    use libva::PictureParameter;
    use libva::SliceParameter;

    use crate::decoders::vp8::backends::vaapi::AssociatedHandle;
    use crate::decoders::vp8::backends::vaapi::TestParams;
    use crate::decoders::vp8::backends::StatelessDecoderBackend;
    use crate::decoders::vp8::decoder::tests::process_ready_frames;
    use crate::decoders::vp8::decoder::tests::run_decoding_loop;
    use crate::decoders::vp8::decoder::Decoder;
    use crate::decoders::BlockingMode;
    use crate::decoders::DecodedHandle;
    use crate::decoders::DynHandle;

    fn get_test_params(
        backend: &dyn StatelessDecoderBackend<Handle = AssociatedHandle>,
    ) -> &Vec<TestParams> {
        backend.get_test_params().downcast_ref::<_>().unwrap()
    }

    fn process_handle(
        handle: &AssociatedHandle,
        dump_yuv: bool,
        expected_crcs: Option<&mut HashSet<&str>>,
        frame_num: i32,
    ) {
        let mut picture = handle.handle_mut();
        let mut backend_handle = picture.dyn_mappable_handle_mut();

        let buffer_size = backend_handle.image_size();
        let mut nv12 = vec![0; buffer_size];

        backend_handle.read(&mut nv12).unwrap();

        if dump_yuv {
            std::fs::write(format!("/tmp/frame{}.yuv", frame_num), &nv12).unwrap();
        }

        let frame_crc = crc32fast::hash(&nv12);

        if let Some(expected_crcs) = expected_crcs {
            let frame_crc = format!("{:08x}", frame_crc);
            let removed = expected_crcs.remove(frame_crc.as_str());
            assert!(
                removed,
                "CRC not found: {:?}, iteration: {:?}",
                frame_crc, frame_num
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_vp8() {
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/test-25fps.vp8");
        const STREAM_CRCS: &str = include_str!("../test_data/test-25fps.vp8.crc");

        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-slice-data-0.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-slice-data-1.bin");
        const TEST_25_FPS_VP8_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-slice-data-2.bin");

        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_0: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-probability-table-0.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_1: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-probability-table-1.bin");
        const TEST_25_FPS_VP8_STREAM_PROBABILITY_TABLE_2: &[u8] =
            include_bytes!("../test_data/test-25fps-vp8-probability-table-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();

            let mut frame_num = 0;
            let display = Display::open().unwrap();

            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let params = &get_test_params(decoder.backend())[frame_num as usize];

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    let pic_param = match params.pic_param {
                        BufferType::PictureParameter(PictureParameter::VP8(ref pic_param)) => {
                            pic_param
                        }
                        _ => panic!(),
                    };

                    let slice_param = match params.slice_param {
                        BufferType::SliceParameter(SliceParameter::VP8(ref slice_param)) => {
                            slice_param
                        }
                        _ => panic!(),
                    };

                    let slice_data = match params.slice_data {
                        BufferType::SliceData(ref data) => data,
                        _ => panic!(),
                    };

                    let iq_matrix = match params.iq_matrix {
                        BufferType::IQMatrix(IQMatrix::VP8(ref iq_matrix)) => iq_matrix,
                        _ => panic!(),
                    };

                    let probability_table = match params.probability_table {
                        BufferType::Probability(ref probability_table) => probability_table,
                        _ => panic!(),
                    };

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
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
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
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
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
                                0xa2, 0x80, 0xe1, 0x92, 0xac, 0x93, 0xd6, 0x27, 0x9c, 0x80, 0x81,
                                0x84, 0x4b, 0x91, 0xb2, 0xce, 0xef, 0xfe, 0xfe,
                            ]
                        );
                        assert_eq!(
                            pic_param.inner().mv_probs[1],
                            [
                                0xa4, 0x80, 0xcc, 0xaa, 0x77, 0xeb, 0x8c, 0xe6, 0xe4, 0x80, 0x82,
                                0x82, 0x4a, 0x94, 0xb4, 0xcb, 0xec, 0xfe, 0xfe,
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

                    frame_num += 1;
                });
            });
        }
    }
}

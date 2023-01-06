// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
#[cfg(test)]
use libva::BufferType;
use libva::Display;
use libva::Picture as VaPicture;
use libva::SegmentParameterVP9;

use crate::decoders::vp9::backends::Result as StatelessBackendResult;
use crate::decoders::vp9::backends::StatelessDecoderBackend;
use crate::decoders::vp9::decoder::Decoder;
use crate::decoders::vp9::decoder::Segmentation;
use crate::decoders::vp9::parser::BitDepth;
use crate::decoders::vp9::parser::Header;
use crate::decoders::vp9::parser::Profile;
use crate::decoders::vp9::parser::ALTREF_FRAME;
use crate::decoders::vp9::parser::GOLDEN_FRAME;
use crate::decoders::vp9::parser::LAST_FRAME;
use crate::decoders::vp9::parser::MAX_SEGMENTS;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
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

/// The number of surfaces to allocate for this codec.
const NUM_SURFACES: usize = 12;

#[cfg(test)]
struct TestParams {
    pic_param: BufferType,
    slice_param: BufferType,
    slice_data: BufferType,
}

impl StreamInfo for &Header {
    fn va_profile(&self) -> anyhow::Result<i32> {
        Ok(match self.profile() {
            Profile::Profile0 => libva::VAProfile::VAProfileVP9Profile0,
            Profile::Profile1 => libva::VAProfile::VAProfileVP9Profile1,
            Profile::Profile2 => libva::VAProfile::VAProfileVP9Profile2,
            Profile::Profile3 => libva::VAProfile::VAProfileVP9Profile3,
        })
    }

    fn rt_format(&self) -> anyhow::Result<u32> {
        Backend::get_rt_format(
            self.profile(),
            self.bit_depth(),
            self.subsampling_x(),
            self.subsampling_y(),
        )
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

    fn get_rt_format(
        profile: Profile,
        bit_depth: BitDepth,
        subsampling_x: bool,
        subsampling_y: bool,
    ) -> Result<u32> {
        match profile {
            Profile::Profile0 => Ok(libva::constants::VA_RT_FORMAT_YUV420),
            Profile::Profile1 => {
                if subsampling_x && !subsampling_y {
                    Ok(libva::constants::VA_RT_FORMAT_YUV422)
                } else if !subsampling_x && !subsampling_y {
                    Ok(libva::constants::VA_RT_FORMAT_YUV444)
                } else {
                    Err(anyhow!(
                        "Unsupported subsampling for profile 1: X: {:?} Y: {:?}",
                        subsampling_x,
                        subsampling_y
                    ))
                }
            }
            Profile::Profile2 => match bit_depth {
                BitDepth::Depth8 => Err(anyhow!(
                    "Unsupported bit depth for profile 2: {:?}",
                    bit_depth
                )),
                BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV420_10),
                BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV420_12),
            },
            Profile::Profile3 => {
                if subsampling_x && !subsampling_y {
                    match bit_depth {
                        BitDepth::Depth8 => Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?  })",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        )),
                        BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV422_10),
                        BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV422_12),
                    }
                } else if !subsampling_x && !subsampling_y {
                    match bit_depth {
                        BitDepth::Depth8 => Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?})",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        )),
                        BitDepth::Depth10 => Ok(libva::constants::VA_RT_FORMAT_YUV444_10),
                        BitDepth::Depth12 => Ok(libva::constants::VA_RT_FORMAT_YUV444_12),
                    }
                } else {
                    Err(anyhow!(
                            "Unsupported (subsampling_x, subsampling_y, bit depth) combination for profile 3: ({:?}, {:?}, {:?})",
                            subsampling_x,
                            subsampling_y,
                            bit_depth
                        ))
                }
            }
        }
    }

    /// Gets the VASurfaceID for the given `picture`.
    fn surface_id(picture: &GenericBackendHandle) -> libva::VASurfaceID {
        picture.surface_id()
    }

    fn build_pic_param(
        hdr: &Header,
        reference_frames: &[Option<AssociatedHandle>; NUM_REF_FRAMES],
    ) -> Result<libva::BufferType> {
        let reference_frames: [u32; 8] = reference_frames
            .iter()
            .map(|h| {
                if let Some(h) = h {
                    Self::surface_id(&h.handle())
                } else {
                    libva::constants::VA_INVALID_SURFACE
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let pic_fields = libva::VP9PicFields::new(
            hdr.subsampling_x() as u32,
            hdr.subsampling_y() as u32,
            hdr.frame_type() as u32,
            hdr.show_frame() as u32,
            hdr.error_resilient_mode() as u32,
            hdr.intra_only() as u32,
            hdr.allow_high_precision_mv() as u32,
            hdr.interpolation_filter() as u32,
            hdr.frame_parallel_decoding_mode() as u32,
            hdr.reset_frame_context() as u32,
            hdr.refresh_frame_context() as u32,
            hdr.frame_context_idx() as u32,
            hdr.seg().enabled() as u32,
            hdr.seg().temporal_update() as u32,
            hdr.seg().update_map() as u32,
            hdr.ref_frame_idx()[LAST_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[LAST_FRAME] as u32,
            hdr.ref_frame_idx()[GOLDEN_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[GOLDEN_FRAME] as u32,
            hdr.ref_frame_idx()[ALTREF_FRAME - 1] as u32,
            hdr.ref_frame_sign_bias()[ALTREF_FRAME] as u32,
            hdr.lossless() as u32,
        );

        let lf = hdr.lf();
        let seg = hdr.seg();

        let seg_pred_prob = if seg.temporal_update() {
            seg.pred_probs()
        } else {
            [0xff, 0xff, 0xff]
        };

        let pic_param = libva::PictureParameterBufferVP9::new(
            hdr.width().try_into().unwrap(),
            hdr.height().try_into().unwrap(),
            reference_frames,
            &pic_fields,
            lf.level(),
            lf.sharpness(),
            hdr.tile_rows_log2(),
            hdr.tile_cols_log2(),
            hdr.uncompressed_header_size_in_bytes().try_into().unwrap(),
            hdr.header_size_in_bytes(),
            seg.tree_probs(),
            seg_pred_prob,
            hdr.profile() as u8,
            hdr.bit_depth() as u8,
        );

        Ok(libva::BufferType::PictureParameter(
            libva::PictureParameter::VP9(pic_param),
        ))
    }

    fn build_slice_param(
        seg: &[Segmentation; MAX_SEGMENTS],
        slice_size: usize,
    ) -> Result<libva::BufferType> {
        let seg_params: std::result::Result<[SegmentParameterVP9; MAX_SEGMENTS], _> = seg
            .iter()
            .map(|s| {
                let seg_flags = libva::VP9SegmentFlags::new(
                    s.reference_frame_enabled as u16,
                    s.reference_frame as u16,
                    s.reference_skip_enabled as u16,
                );

                libva::SegmentParameterVP9::new(
                    &seg_flags,
                    s.lvl_lookup,
                    s.luma_ac_quant_scale,
                    s.luma_dc_quant_scale,
                    s.chroma_ac_quant_scale,
                    s.chroma_dc_quant_scale,
                )
            })
            .collect::<Vec<_>>()
            .try_into();

        let seg_params = match seg_params {
            Ok(seg_params) => seg_params,

            // Impossible, this is just a detour to collect into a fixed-size
            // array whose size is the same size of the `seg` argument.
            Err(_) => panic!("Invalid segment parameters"),
        };

        Ok(libva::BufferType::SliceParameter(
            libva::SliceParameter::VP9(libva::SliceParameterBufferVP9::new(
                slice_size as u32,
                0,
                libva::constants::VA_SLICE_DATA_FLAG_ALL,
                seg_params,
            )),
        ))
    }

    #[cfg(test)]
    fn save_params(
        &mut self,
        pic_param: BufferType,
        slice_param: BufferType,
        slice_data: BufferType,
    ) {
        let test_params = TestParams {
            pic_param,
            slice_param,
            slice_data,
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
        reference_frames: &[Option<Self::Handle>; NUM_REF_FRAMES],
        bitstream: &[u8],
        timestamp: u64,
        segmentation: &[Segmentation; MAX_SEGMENTS],
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        self.backend.negotiation_status = NegotiationStatus::Negotiated;

        let context = self.backend.metadata_state.context()?;

        let pic_param =
            context.create_buffer(Backend::build_pic_param(picture, reference_frames)?)?;

        #[cfg(test)]
        {
            let seg = segmentation.clone();
            self.save_params(
                Backend::build_pic_param(picture, reference_frames)?,
                Backend::build_slice_param(&seg, bitstream.len())?,
                libva::BufferType::SliceData(Vec::from(bitstream)),
            );
        }

        let slice_param =
            context.create_buffer(Backend::build_slice_param(segmentation, bitstream.len())?)?;

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
        va_picture.add_buffer(pic_param);
        va_picture.add_buffer(slice_param);
        va_picture.add_buffer(slice_data);

        let va_picture = va_picture.begin()?.render()?.end()?;

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
    fn get_test_params(&self) -> &dyn std::any::Any {
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

    use libva::BufferType;
    use libva::Display;
    use libva::PictureParameter;
    use libva::SliceParameter;

    use crate::decoders::vp9::backends::vaapi::AssociatedHandle;
    use crate::decoders::vp9::backends::vaapi::TestParams;
    use crate::decoders::vp9::backends::StatelessDecoderBackend;
    use crate::decoders::vp9::decoder::tests::process_ready_frames;
    use crate::decoders::vp9::decoder::tests::run_decoding_loop;
    use crate::decoders::vp9::decoder::Decoder;
    use crate::decoders::vp9::parser::NUM_REF_FRAMES;
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
        expected_crcs: Option<&Vec<&str>>,
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
            let contains = expected_crcs.contains(&frame_crc.as_ref());
            if !contains {
                panic!("CRC not found: {:?}, iteration: {:?}", frame_crc, frame_num);
            }
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_vp9() {
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/test-25fps.vp9");
        const STREAM_CRCS: &str = include_str!("../test_data/test-25fps.vp9.crc");

        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-0.bin");
        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-1.bin");
        const TEST_25_FPS_VP9_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../test_data/test-25fps-vp9-slice-data-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let params = &get_test_params(decoder.backend())[frame_num as usize];

                    process_handle(handle, false, Some(&expected_crcs), frame_num);

                    let pic_param = match params.pic_param {
                        BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                            pic_param
                        }
                        _ => panic!(),
                    };

                    let slice_param = match params.slice_param {
                        BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                            slice_param
                        }
                        _ => panic!(),
                    };

                    let slice_data = match params.slice_data {
                        BufferType::SliceData(ref data) => data,
                        _ => panic!(),
                    };

                    if frame_num == 0 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(
                            pic_param.inner().reference_frames,
                            [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                        );

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 9);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                        assert_eq!(pic_param.inner().first_partition_size, 120);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 10674);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(seg_param.filter_level, [[10, 0], [9, 9], [8, 8], [8, 8]]);
                            assert_eq!(seg_param.luma_ac_quant_scale, 72);
                            assert_eq!(seg_param.luma_dc_quant_scale, 62);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 72);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 62);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_0);
                    } else if frame_num == 1 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 15);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 11);
                        assert_eq!(pic_param.inner().first_partition_size, 48);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 2390);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(
                                seg_param.filter_level,
                                [[16, 0], [15, 15], [14, 14], [14, 14]]
                            );
                            assert_eq!(seg_param.luma_ac_quant_scale, 136);
                            assert_eq!(seg_param.luma_dc_quant_scale, 111);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 136);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 111);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_1);
                    } else if frame_num == 2 {
                        assert_eq!(pic_param.inner().frame_width, 320);
                        assert_eq!(pic_param.inner().frame_height, 240);
                        assert_eq!(pic_param.inner().reference_frames, [0, 0, 1, 0, 0, 0, 0, 0]);

                        // Safe because this bitfield is initialized by the decoder.
                        assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                            libva::VP9PicFields::new(
                                1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1, 0,
                            )
                            .inner()
                            .value
                        });

                        assert_eq!(pic_param.inner().filter_level, 36);
                        assert_eq!(pic_param.inner().sharpness_level, 0);
                        assert_eq!(pic_param.inner().log2_tile_rows, 0);
                        assert_eq!(pic_param.inner().log2_tile_columns, 0);
                        assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                        assert_eq!(pic_param.inner().first_partition_size, 9);
                        assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                        assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                        assert_eq!(pic_param.inner().profile, 0);
                        assert_eq!(pic_param.inner().bit_depth, 8);

                        assert_eq!(slice_param.inner().slice_data_size, 108);
                        assert_eq!(slice_param.inner().slice_data_offset, 0);
                        assert_eq!(
                            slice_param.inner().slice_data_flag,
                            libva::constants::VA_SLICE_DATA_FLAG_ALL
                        );

                        for seg_param in &slice_param.inner().seg_param {
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                            assert_eq!(
                                seg_param.filter_level,
                                [[38, 0], [36, 36], [34, 34], [34, 34]]
                            );
                            assert_eq!(seg_param.luma_ac_quant_scale, 864);
                            assert_eq!(seg_param.luma_dc_quant_scale, 489);
                            assert_eq!(seg_param.chroma_ac_quant_scale, 864);
                            assert_eq!(seg_param.chroma_dc_quant_scale, 489);
                        }

                        assert_eq!(&slice_data[..], TEST_25_FPS_VP9_STREAM_SLICE_DATA_2);
                    }

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_vp90_2_10_show_existing_frame2_vp9() {
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2.vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/vp90_2_10_show_existing_frame2.vp9.ivf.crc");

        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-0.bin");
        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-1.bin");
        const TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_2: &[u8] =
            include_bytes!("../test_data/vp90_2_10_show_existing_frame2-vp9-ivf-slice-data-2.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();

            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let params = get_test_params(decoder.backend()).get(frame_num as usize);

                    process_handle(handle, false, Some(&expected_crcs), frame_num);

                    if let Some(params) = params {
                        let pic_param = match params.pic_param {
                            BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                                pic_param
                            }
                            _ => panic!(),
                        };

                        let slice_param = match params.slice_param {
                            BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                                slice_param
                            }
                            _ => panic!(),
                        };

                        let slice_data = match params.slice_data {
                            BufferType::SliceData(ref data) => data,
                            _ => panic!(),
                        };

                        if frame_num == 0 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 36);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 106);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 4075);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[38, 0], [36, 36], [34, 34], [34, 34]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 593);
                                assert_eq!(seg_param.luma_dc_quant_scale, 369);
                                assert_eq!(seg_param.luma_ac_quant_scale, 593);
                                assert_eq!(seg_param.luma_dc_quant_scale, 369);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_0
                            );
                        } else if frame_num == 1 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 0, 0, 0, 1, 4, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 56);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 68);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 2598);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[58, 0], [56, 56], [54, 54], [54, 54]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 663);
                                assert_eq!(seg_param.luma_dc_quant_scale, 400);
                                assert_eq!(seg_param.luma_ac_quant_scale, 663);
                                assert_eq!(seg_param.luma_dc_quant_scale, 400);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_1
                            );
                        } else if frame_num == 2 {
                            assert_eq!(pic_param.inner().frame_width, 352);
                            assert_eq!(pic_param.inner().frame_height, 288);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [0, 0, 1, 0, 1, 0, 0, 0]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 1, 0, 0, 0, 4, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 42);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 18);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 447);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[44, 0], [42, 42], [40, 40], [40, 40]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 1151);
                                assert_eq!(seg_param.luma_dc_quant_scale, 640);
                                assert_eq!(seg_param.luma_ac_quant_scale, 1151);
                                assert_eq!(seg_param.luma_dc_quant_scale, 640);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_VP90_2_10_SHOW_EXISTING_FRAME2_STREAM_SLICE_DATA_2
                            );
                        }
                    }

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_vp90_2_10_show_existing_frame_vp9() {
        // Remuxed from the original matroska source in libvpx using ffmpeg:
        // ffmpeg -i vp90-2-10-show-existing-frame.webm/vp90-2-10-show-existing-frame.webm -c:v copy /tmp/vp90-2-10-show-existing-frame.vp9.ivf
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/vp90-2-10-show-existing-frame.vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/vp90-2-10-show-existing-frame.vp9.ivf.crc");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();

            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let _params = get_test_params(decoder.backend()).get(frame_num as usize);

                    process_handle(handle, false, Some(&expected_crcs), frame_num);

                    frame_num += 1;
                });
            });
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_resolution_change_500frames_vp9() {
        // Remuxed from the original matroska source in libvpx using ffmpeg:
        // ffmpeg -i vp90-2-10-show-existing-frame.webm/vp90-2-10-show-existing-frame.webm -c:v copy /tmp/vp90-2-10-show-existing-frame.vp9.ivf
        // There are some weird padding issues introduced by GStreamer for
        // resolutions that are not multiple of 4, so we're ignoring CRCs for
        // this one.
        const TEST_STREAM: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9.ivf");
        const STREAM_CRCS: &str =
            include_str!("../test_data/resolution_change_500frames-vp9.ivf.crc");

        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_0: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-0.bin");
        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_1: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-1.bin");
        const TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_54: &[u8] =
            include_bytes!("../test_data/resolution_change_500frames-vp9-ivf-slice-data-54.bin");

        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let expected_crcs = STREAM_CRCS.lines().collect::<Vec<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    // Notice that the VP9 codec can choose to redisplay frames,
                    // in which case, no test parameters are recorded, because
                    // no decode operation is made.
                    let params = get_test_params(decoder.backend()).get(frame_num as usize);

                    // GStreamer adds padding otherwise, so we introduce this
                    // check so as to not fail because of that, as some of the
                    // intermediary resolutions in this file fail this
                    // condition.
                    let expected_crcs = if handle.display_resolution().width % 4 == 0 {
                        Some(&expected_crcs)
                    } else {
                        None
                    };

                    process_handle(handle, false, expected_crcs, frame_num);

                    if let Some(params) = params {
                        let pic_param = match params.pic_param {
                            BufferType::PictureParameter(PictureParameter::VP9(ref pic_param)) => {
                                pic_param
                            }
                            _ => panic!(),
                        };

                        let slice_param = match params.slice_param {
                            BufferType::SliceParameter(SliceParameter::VP9(ref slice_param)) => {
                                slice_param
                            }
                            _ => panic!(),
                        };

                        let slice_data = match params.slice_data {
                            BufferType::SliceData(ref data) => data,
                            _ => panic!(),
                        };

                        if frame_num == 0 {
                            assert_eq!(pic_param.inner().frame_width, 640);
                            assert_eq!(pic_param.inner().frame_height, 360);
                            assert_eq!(
                                pic_param.inner().reference_frames,
                                [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 0);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 1);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 134);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 38676);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[0, 0], [0, 0], [0, 0], [0, 0]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 31);
                                assert_eq!(seg_param.luma_dc_quant_scale, 27);
                                assert_eq!(seg_param.luma_ac_quant_scale, 31);
                                assert_eq!(seg_param.luma_dc_quant_scale, 27);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_0
                            );
                        } else if frame_num == 1 {
                            assert_eq!(pic_param.inner().frame_width, 640);
                            assert_eq!(pic_param.inner().frame_height, 360);
                            assert_eq!(pic_param.inner().reference_frames, [0; NUM_REF_FRAMES]);
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 1, 0, 0, 0, 1, 4, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 2, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 3);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 1);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 10);
                            assert_eq!(pic_param.inner().first_partition_size, 74);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 3866);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[4, 0], [3, 3], [2, 2], [2, 2]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 58);
                                assert_eq!(seg_param.luma_dc_quant_scale, 50);
                                assert_eq!(seg_param.luma_ac_quant_scale, 58);
                                assert_eq!(seg_param.luma_dc_quant_scale, 50);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_1
                            );
                        } else if frame_num == 54 {
                            assert_eq!(pic_param.inner().frame_width, 426);
                            assert_eq!(pic_param.inner().frame_height, 240);
                            // GStreamer flushes before new_sequence, TODO:
                            // check whether this impacts the fluster score.
                            // assert_eq!(
                            //     pic_param.inner().reference_frames,
                            //     [libva::constants::VA_INVALID_SURFACE; NUM_REF_FRAMES]
                            // );
                            // Safe because this bitfield is initialized by the decoder.
                            assert_eq!(unsafe { pic_param.inner().pic_fields.value }, unsafe {
                                libva::VP9PicFields::new(
                                    1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0,
                                )
                                .inner()
                                .value
                            });

                            assert_eq!(pic_param.inner().filter_level, 0);
                            assert_eq!(pic_param.inner().sharpness_level, 0);
                            assert_eq!(pic_param.inner().log2_tile_rows, 0);
                            assert_eq!(pic_param.inner().log2_tile_columns, 0);
                            assert_eq!(pic_param.inner().frame_header_length_in_bytes, 18);
                            assert_eq!(pic_param.inner().first_partition_size, 75);
                            assert_eq!(pic_param.inner().mb_segment_tree_probs, [0; 7]);
                            assert_eq!(pic_param.inner().segment_pred_probs, [0xff; 3]);
                            assert_eq!(pic_param.inner().profile, 0);
                            assert_eq!(pic_param.inner().bit_depth, 8);

                            assert_eq!(slice_param.inner().slice_data_size, 19004);
                            assert_eq!(slice_param.inner().slice_data_offset, 0);
                            assert_eq!(
                                slice_param.inner().slice_data_flag,
                                libva::constants::VA_SLICE_DATA_FLAG_ALL
                            );

                            for seg_param in &slice_param.inner().seg_param {
                                // Safe because this bitfield is initialized by the decoder.
                                assert_eq!(unsafe { seg_param.segment_flags.value }, 0);
                                assert_eq!(
                                    seg_param.filter_level,
                                    [[0, 0], [0, 0], [0, 0], [0, 0]]
                                );
                                assert_eq!(seg_param.luma_ac_quant_scale, 33);
                                assert_eq!(seg_param.luma_dc_quant_scale, 29);
                                assert_eq!(seg_param.luma_ac_quant_scale, 33);
                                assert_eq!(seg_param.luma_dc_quant_scale, 29);
                            }

                            assert_eq!(
                                &slice_data[..],
                                TEST_RESOLUTION_CHANGE_500FRAMES_STREAM_SLICE_DATA_54
                            );
                        }
                    }

                    frame_num += 1;
                });
            });
        }
    }
}

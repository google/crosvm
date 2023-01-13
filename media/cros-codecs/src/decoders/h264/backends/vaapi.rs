// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Context as AnyhowContext;
use anyhow::Result;
use libva::BufferType;
use libva::Display;
use libva::IQMatrix;
use libva::IQMatrixBufferH264;
use libva::Picture as VaPicture;
use libva::PictureNew;
use libva::PictureParameter;
use libva::PictureParameterBufferH264;
use libva::SliceParameter;
use log::debug;

use crate::decoders::h264::backends::Result as StatelessBackendResult;
use crate::decoders::h264::backends::StatelessDecoderBackend;
use crate::decoders::h264::decoder::Decoder;
use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::dpb::DpbEntry;
use crate::decoders::h264::parser::Level;
use crate::decoders::h264::parser::Pps;
use crate::decoders::h264::parser::Profile;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::Field;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::h264::picture::Reference;
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
use crate::DecodedFormat;
use crate::Resolution;

#[cfg(test)]
#[derive(Default)]
struct TestParams {
    pic_param: Option<BufferType>,
    iq_matrix: Option<BufferType>,
    slice_param: Option<BufferType>,
    slice_data: Option<BufferType>,
}

#[cfg(test)]
impl TestParams {
    fn save_pic_params(&mut self, pic_param: BufferType, iq_matrix: BufferType) {
        self.pic_param = Some(pic_param);
        self.iq_matrix = Some(iq_matrix);
    }

    fn save_slice_params(&mut self, slice_param: BufferType) {
        self.slice_param = Some(slice_param);
    }

    fn save_slice_data(&mut self, slice_data: BufferType) {
        self.slice_data = Some(slice_data);
    }
}

impl StreamInfo for &Sps {
    fn va_profile(&self) -> anyhow::Result<i32> {
        let profile_idc = self.profile_idc();
        let profile = Profile::n(profile_idc)
            .with_context(|| format!("Invalid profile_idc {:?}", profile_idc))?;

        match profile {
            Profile::Baseline => {
                if self.constraint_set0_flag() {
                    Ok(libva::VAProfile::VAProfileH264ConstrainedBaseline)
                } else {
                    Err(anyhow!(
                        "Unsupported stream: profile_idc=66, but constraint_set0_flag is unset"
                    ))
                }
            }
            Profile::Main => Ok(libva::VAProfile::VAProfileH264Main),
            Profile::High => Ok(libva::VAProfile::VAProfileH264High),
        }
    }

    fn rt_format(&self) -> anyhow::Result<u32> {
        let bit_depth_luma = self.bit_depth_chroma_minus8() + 8;
        let chroma_format_idc = self.chroma_format_idc();

        match bit_depth_luma {
            8 => match chroma_format_idc {
                0 | 1 => Ok(libva::constants::VA_RT_FORMAT_YUV420),
                _ => Err(anyhow!(
                    "Unsupported chroma_format_idc: {}",
                    chroma_format_idc
                )),
            },
            _ => Err(anyhow!("Unsupported bit depth: {}", bit_depth_luma)),
        }
    }

    fn min_num_surfaces(&self) -> usize {
        self.max_dpb_frames().unwrap() + 4
    }

    fn coded_size(&self) -> (u32, u32) {
        (self.width(), self.height())
    }

    fn visible_rect(&self) -> ((u32, u32), (u32, u32)) {
        let rect = self.visible_rectangle();

        ((rect.min.x, rect.min.y), (rect.max.x, rect.max.y))
    }
}

/// H.264 stateless decoder backend for VA-API.
struct Backend {
    backend: VaapiBackend<Sps>,

    /// The current picture being worked on.
    current_picture: Option<VaPicture<PictureNew>>,

    #[cfg(test)]
    /// Test params. Saves the metadata sent to VA-API for the purposes of
    /// testing.
    test_params: TestParams,
}

impl Backend {
    /// Creates a new codec backend for H.264.
    fn new(display: Rc<libva::Display>) -> Result<Self> {
        Ok(Self {
            backend: VaapiBackend::new(display),
            current_picture: Default::default(),

            #[cfg(test)]
            test_params: Default::default(),
        })
    }

    /// Gets the VASurfaceID for the given `picture`.
    fn surface_id(handle: &Option<VADecodedHandle>) -> libva::VASurfaceID {
        match handle {
            None => libva::constants::VA_INVALID_SURFACE,
            Some(handle) => handle.handle().surface_id(),
        }
    }

    /// Fills the internal `va_pic` picture parameter with data from `h264_pic`
    fn fill_va_h264_pic(
        h264_pic: &PictureData,
        surface_id: libva::VASurfaceID,
        merge_other_field: bool,
    ) -> libva::PictureH264 {
        let mut flags = 0;
        let frame_idx = if matches!(h264_pic.reference(), Reference::LongTerm) {
            flags |= libva::constants::VA_PICTURE_H264_LONG_TERM_REFERENCE;
            h264_pic.long_term_frame_idx
        } else {
            if matches!(h264_pic.reference(), Reference::ShortTerm { .. }) {
                flags |= libva::constants::VA_PICTURE_H264_SHORT_TERM_REFERENCE;
            }

            h264_pic.frame_num
        };

        let top_field_order_cnt;
        let bottom_field_order_cnt;

        match h264_pic.field {
            Field::Frame => {
                top_field_order_cnt = h264_pic.top_field_order_cnt;
                bottom_field_order_cnt = h264_pic.bottom_field_order_cnt;
            }
            Field::Top => {
                if merge_other_field && h264_pic.other_field().is_some() {
                    bottom_field_order_cnt = h264_pic
                        .other_field_unchecked()
                        .borrow()
                        .bottom_field_order_cnt;
                } else {
                    flags |= libva::constants::VA_PICTURE_H264_TOP_FIELD;
                    bottom_field_order_cnt = 0;
                }

                top_field_order_cnt = h264_pic.top_field_order_cnt;
            }
            Field::Bottom => {
                if merge_other_field && h264_pic.other_field().is_some() {
                    top_field_order_cnt = h264_pic
                        .other_field_unchecked()
                        .borrow()
                        .top_field_order_cnt;
                } else {
                    flags |= libva::constants::VA_PICTURE_H264_BOTTOM_FIELD;
                    top_field_order_cnt = 0;
                }

                bottom_field_order_cnt = h264_pic.bottom_field_order_cnt;
            }
        }

        libva::PictureH264::new(
            surface_id,
            frame_idx as u32,
            flags,
            top_field_order_cnt,
            bottom_field_order_cnt,
        )
    }

    /// Builds an invalid VaPictureH264. These pictures are used to fill empty
    /// array slots there is no data to fill them with.
    fn build_invalid_va_h264_pic() -> libva::PictureH264 {
        libva::PictureH264::new(
            libva::constants::VA_INVALID_ID,
            0,
            libva::constants::VA_PICTURE_H264_INVALID,
            0,
            0,
        )
    }

    fn build_iq_matrix(pps: &Pps) -> BufferType {
        let mut scaling_list4x4 = [[0; 16]; 6];
        let mut scaling_list8x8 = [[0; 64]; 2];

        (0..6).for_each(|i| {
            Decoder::<VADecodedHandle>::get_raster_from_zigzag_4x4(
                pps.scaling_lists_4x4()[i],
                &mut scaling_list4x4[i],
            );
        });

        (0..2).for_each(|i| {
            Decoder::<VADecodedHandle>::get_raster_from_zigzag_8x8(
                pps.scaling_lists_8x8()[i],
                &mut scaling_list8x8[i],
            );
        });

        BufferType::IQMatrix(IQMatrix::H264(IQMatrixBufferH264::new(
            scaling_list4x4,
            scaling_list8x8,
        )))
    }

    fn build_pic_param(
        slice: &Slice<impl AsRef<[u8]>>,
        current_picture: &PictureData,
        current_surface_id: libva::VASurfaceID,
        dpb: &Dpb<VADecodedHandle>,
        sps: &Sps,
        pps: &Pps,
    ) -> Result<BufferType> {
        let curr_pic = Backend::fill_va_h264_pic(current_picture, current_surface_id, false);

        let mut refs = vec![];
        let mut va_refs = vec![];

        dpb.get_short_term_refs(&mut refs);
        refs.retain(|handle| {
            let pic = handle.0.borrow();
            !pic.nonexisting && !pic.is_second_field()
        });

        for handle in &refs {
            let ref_pic = handle.0.borrow();
            let surface_id = Backend::surface_id(&handle.1);
            let pic = Backend::fill_va_h264_pic(&ref_pic, surface_id, true);
            va_refs.push(pic);
        }

        refs.clear();

        dpb.get_long_term_refs(&mut refs);
        refs.retain(|handle| {
            let pic = handle.0.borrow();
            !pic.is_second_field()
        });

        for handle in &refs {
            let ref_pic = handle.0.borrow();
            let surface_id = Backend::surface_id(&handle.1);
            let pic = Backend::fill_va_h264_pic(&ref_pic, surface_id, true);
            va_refs.push(pic);
        }

        for _ in va_refs.len()..16 {
            va_refs.push(Backend::build_invalid_va_h264_pic());
        }

        refs.clear();

        let seq_fields = libva::H264SeqFields::new(
            sps.chroma_format_idc() as u32,
            sps.separate_colour_plane_flag() as u32,
            sps.gaps_in_frame_num_value_allowed_flag() as u32,
            sps.frame_mbs_only_flag() as u32,
            sps.mb_adaptive_frame_field_flag() as u32,
            sps.direct_8x8_inference_flag() as u32,
            (sps.level_idc() > Level::L3_1) as u32, /* see A.3.3.2 */
            sps.log2_max_frame_num_minus4() as u32,
            sps.pic_order_cnt_type() as u32,
            sps.log2_max_pic_order_cnt_lsb_minus4() as u32,
            sps.delta_pic_order_always_zero_flag() as u32,
        );
        let interlaced = !sps.frame_mbs_only_flag() as u32;
        let picture_height_in_mbs_minus1 =
            ((sps.pic_height_in_map_units_minus1() + 1) << interlaced) - 1;

        let pic_fields = libva::H264PicFields::new(
            pps.entropy_coding_mode_flag() as u32,
            pps.weighted_pred_flag() as u32,
            pps.weighted_bipred_idc() as u32,
            pps.transform_8x8_mode_flag() as u32,
            slice.header().field_pic_flag() as u32,
            pps.constrained_intra_pred_flag() as u32,
            pps.bottom_field_pic_order_in_frame_present_flag() as u32,
            pps.deblocking_filter_control_present_flag() as u32,
            pps.redundant_pic_cnt_present_flag() as u32,
            (current_picture.nal_ref_idc != 0) as u32,
        );

        let va_refs = va_refs.try_into();
        let va_refs = match va_refs {
            Ok(va_refs) => va_refs,
            Err(_) => {
                panic!("Bug: wrong number of references, expected 16");
            }
        };

        let pic_param = PictureParameterBufferH264::new(
            curr_pic,
            va_refs,
            u16::try_from(sps.pic_width_in_mbs_minus1())?,
            u16::try_from(picture_height_in_mbs_minus1)?,
            sps.bit_depth_luma_minus8(),
            sps.bit_depth_chroma_minus8(),
            u8::try_from(sps.max_num_ref_frames())?,
            &seq_fields,
            0, /* FMO not supported by VA */
            0, /* FMO not supported by VA */
            0, /* FMO not supported by VA */
            pps.pic_init_qp_minus26(),
            pps.pic_init_qs_minus26(),
            pps.chroma_qp_index_offset(),
            pps.second_chroma_qp_index_offset(),
            &pic_fields,
            slice.header().frame_num(),
        );

        Ok(BufferType::PictureParameter(PictureParameter::H264(
            pic_param,
        )))
    }

    fn fill_ref_pic_list(ref_list_x: &[DpbEntry<VADecodedHandle>]) -> [libva::PictureH264; 32] {
        let mut va_pics = vec![];

        for handle in ref_list_x {
            let pic = handle.0.borrow();
            let surface_id = Backend::surface_id(&handle.1);
            let merge = matches!(pic.field, Field::Frame);
            let va_pic = Backend::fill_va_h264_pic(&pic, surface_id, merge);

            va_pics.push(va_pic);
        }

        for _ in va_pics.len()..32 {
            va_pics.push(Backend::build_invalid_va_h264_pic());
        }

        let va_pics: [libva::PictureH264; 32] = match va_pics.try_into() {
            Ok(va_pics) => va_pics,
            Err(e) => panic!(
                "Bug: wrong number of references, expected 32, got {:?}",
                e.len()
            ),
        };

        va_pics
    }

    fn build_slice_param(
        slice: &Slice<impl AsRef<[u8]>>,
        ref_list_0: &[DpbEntry<VADecodedHandle>],
        ref_list_1: &[DpbEntry<VADecodedHandle>],
        sps: &Sps,
        pps: &Pps,
    ) -> Result<BufferType> {
        let hdr = slice.header();
        let nalu = slice.nalu();

        let ref_list_0 = Backend::fill_ref_pic_list(ref_list_0);
        let ref_list_1 = Backend::fill_ref_pic_list(ref_list_1);
        let pwt = hdr.pred_weight_table();

        let mut luma_weight_l0_flag = false;
        let mut chroma_weight_l0_flag = false;
        let mut luma_weight_l0 = [0i16; 32];
        let mut luma_offset_l0 = [0i16; 32];
        let mut chroma_weight_l0: [[i16; 2]; 32] = [[0i16; 2]; 32];
        let mut chroma_offset_l0: [[i16; 2]; 32] = [[0i16; 2]; 32];

        let mut luma_weight_l1_flag = false;
        let mut chroma_weight_l1_flag = false;
        let mut luma_weight_l1 = [0i16; 32];
        let mut luma_offset_l1 = [0i16; 32];
        let mut chroma_weight_l1: [[i16; 2]; 32] = [[0i16; 2]; 32];
        let mut chroma_offset_l1: [[i16; 2]; 32] = [[0i16; 2]; 32];

        let mut fill_l0 = false;
        let mut fill_l1 = false;

        if pps.weighted_pred_flag() && (hdr.slice_type().is_p() || hdr.slice_type().is_sp()) {
            fill_l0 = true;
        } else if pps.weighted_bipred_idc() == 1 && hdr.slice_type().is_b() {
            fill_l0 = true;
            fill_l1 = true;
        }

        if fill_l0 {
            luma_weight_l0_flag = true;

            for i in 0..=hdr.num_ref_idx_l0_active_minus1() as usize {
                luma_weight_l0[i] = pwt.luma_weight_l0()[i];
                luma_offset_l0[i] = i16::from(pwt.luma_offset_l0()[i]);
            }

            chroma_weight_l0_flag = sps.chroma_array_type() != 0;
            if chroma_weight_l0_flag {
                for i in 0..=hdr.num_ref_idx_l0_active_minus1() as usize {
                    for j in 0..2 {
                        chroma_weight_l0[i][j] = pwt.chroma_weight_l0()[i][j];
                        chroma_offset_l0[i][j] = i16::from(pwt.chroma_offset_l0()[i][j]);
                    }
                }
            }
        }

        if fill_l1 {
            luma_weight_l1_flag = true;

            luma_weight_l1[..(hdr.num_ref_idx_l1_active_minus1() as usize + 1)].clone_from_slice(
                &pwt.luma_weight_l1()[..(hdr.num_ref_idx_l1_active_minus1() as usize + 1)],
            );
            luma_offset_l1[..(hdr.num_ref_idx_l1_active_minus1() as usize + 1)].clone_from_slice(
                &pwt.luma_offset_l1()[..(hdr.num_ref_idx_l1_active_minus1() as usize + 1)],
            );

            chroma_weight_l1_flag = sps.chroma_array_type() != 0;
            if chroma_weight_l1_flag {
                for i in 0..=hdr.num_ref_idx_l1_active_minus1() as usize {
                    for j in 0..2 {
                        chroma_weight_l1[i][j] = pwt.chroma_weight_l1()[i][j];
                        chroma_offset_l1[i][j] = i16::from(pwt.chroma_offset_l1()[i][j]);
                    }
                }
            }
        }

        let slice_param = libva::SliceParameterBufferH264::new(
            nalu.size() as u32,
            0,
            libva::constants::VA_SLICE_DATA_FLAG_ALL,
            hdr.header_bit_size() as u16,
            hdr.first_mb_in_slice() as u16,
            *hdr.slice_type() as u8,
            hdr.direct_spatial_mv_pred_flag() as u8,
            hdr.num_ref_idx_l0_active_minus1(),
            hdr.num_ref_idx_l1_active_minus1(),
            hdr.cabac_init_idc(),
            hdr.slice_qp_delta(),
            hdr.disable_deblocking_filter_idc(),
            hdr.slice_alpha_c0_offset_div2(),
            hdr.slice_beta_offset_div2(),
            ref_list_0,
            ref_list_1,
            pwt.luma_log2_weight_denom(),
            pwt.chroma_log2_weight_denom(),
            luma_weight_l0_flag as u8,
            luma_weight_l0,
            luma_offset_l0,
            chroma_weight_l0_flag as u8,
            chroma_weight_l0,
            chroma_offset_l0,
            luma_weight_l1_flag as u8,
            luma_weight_l1,
            luma_offset_l1,
            chroma_weight_l1_flag as u8,
            chroma_weight_l1,
            chroma_offset_l1,
        );

        Ok(BufferType::SliceParameter(SliceParameter::H264(
            slice_param,
        )))
    }
}

impl VideoDecoderBackend for Backend {
    type Handle = VADecodedHandle;

    fn num_resources_total(&self) -> usize {
        self.backend.num_resources_total()
    }

    fn num_resources_left(&self) -> usize {
        self.backend.num_resources_left()
    }

    fn format(&self) -> Option<DecodedFormat> {
        self.backend.format()
    }

    fn try_format(&mut self, format: DecodedFormat) -> DecoderResult<()> {
        self.backend.try_format(format)
    }

    fn coded_resolution(&self) -> Option<Resolution> {
        self.backend.coded_resolution()
    }

    fn display_resolution(&self) -> Option<Resolution> {
        self.backend.display_resolution()
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

impl StatelessDecoderBackend for Backend {
    fn new_sequence(&mut self, sps: &Sps) -> StatelessBackendResult<()> {
        self.backend.metadata_state.open(sps, None)?;
        self.backend.negotiation_status = NegotiationStatus::Possible(Box::new(sps.clone()));

        Ok(())
    }

    fn handle_picture(
        &mut self,
        picture: &PictureData,
        timestamp: u64,
        sps: &Sps,
        pps: &Pps,
        dpb: &Dpb<Self::Handle>,
        slice: &Slice<&[u8]>,
    ) -> StatelessBackendResult<()> {
        debug!(
            "Va-API backend: handle_picture for timestamp {:?}",
            timestamp
        );

        self.backend.negotiation_status = NegotiationStatus::Negotiated;

        let metadata = self.backend.metadata_state.get_parsed()?;
        let context = &metadata.context;

        let va_pic = &mut self.current_picture.as_mut().unwrap();
        let surface_id = va_pic.surface().id();

        let pic_param = Backend::build_pic_param(slice, picture, surface_id, dpb, sps, pps)?;
        let pic_param = context.create_buffer(pic_param)?;

        let iq_matrix = Backend::build_iq_matrix(pps);
        let iq_matrix = context.create_buffer(iq_matrix)?;

        #[cfg(test)]
        self.test_params.save_pic_params(
            Backend::build_pic_param(slice, picture, surface_id, dpb, sps, pps)?,
            Backend::build_iq_matrix(pps),
        );

        va_pic.add_buffer(pic_param);
        va_pic.add_buffer(iq_matrix);

        Ok(())
    }

    fn decode_slice(
        &mut self,
        slice: &Slice<&[u8]>,
        sps: &Sps,
        pps: &Pps,
        _: &Dpb<Self::Handle>,
        ref_pic_list0: &[DpbEntry<Self::Handle>],
        ref_pic_list1: &[DpbEntry<Self::Handle>],
    ) -> StatelessBackendResult<()> {
        let metadata = self.backend.metadata_state.get_parsed()?;
        let context = &metadata.context;

        let slice_param = context.create_buffer(Backend::build_slice_param(
            slice,
            ref_pic_list0,
            ref_pic_list1,
            sps,
            pps,
        )?)?;

        #[cfg(test)]
        self.test_params
            .save_slice_params(Backend::build_slice_param(
                slice,
                ref_pic_list0,
                ref_pic_list1,
                sps,
                pps,
            )?);

        let cur_va_pic = &mut self.current_picture.as_mut().unwrap();
        cur_va_pic.add_buffer(slice_param);

        let slice_data =
            context.create_buffer(BufferType::SliceData(Vec::from(slice.nalu().as_ref())))?;

        #[cfg(test)]
        self.test_params
            .save_slice_data(BufferType::SliceData(Vec::from(slice.nalu().as_ref())));

        cur_va_pic.add_buffer(slice_data);

        Ok(())
    }

    fn submit_picture(
        &mut self,
        _: &PictureData,
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        let current_picture = self.current_picture.take().unwrap();
        let timestamp = current_picture.timestamp();
        let surface_id = current_picture.surface().id();
        let current_picture = current_picture.begin()?.render()?.end()?;

        let metadata = self.backend.metadata_state.get_parsed()?;

        let backend_handle = if block {
            let current_picture = current_picture.sync()?;

            Rc::new(RefCell::new(GenericBackendHandle::new_ready(
                current_picture,
                Rc::clone(&metadata.map_format),
                metadata.display_resolution,
            )))
        } else {
            let backend_handle =
                Rc::new(RefCell::new(GenericBackendHandle::new_pending(surface_id)));

            self.backend.pending_jobs.push_back(PendingJob {
                va_picture: current_picture,
                codec_picture: Rc::clone(&backend_handle),
            });

            backend_handle
        };

        self.backend
            .build_va_decoded_handle(&backend_handle, timestamp)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
    }

    fn new_picture(&mut self, _: &PictureData, timestamp: u64) -> StatelessBackendResult<()> {
        let metadata = self.backend.metadata_state.get_parsed_mut()?;

        let surface = metadata
            .surface_pool
            .get_surface()
            .ok_or(StatelessBackendError::OutOfResources)?;

        let va_pic = VaPicture::new(timestamp, Rc::clone(&metadata.context), surface);

        self.current_picture = Some(va_pic);

        Ok(())
    }

    fn new_field_picture(
        &mut self,
        _: &PictureData,
        timestamp: u64,
        first_field: &Self::Handle,
    ) -> StatelessBackendResult<()> {
        // Block on the first field if it is not ready yet.
        let backend_handle = first_field.handle();
        if !backend_handle.is_ready() {
            drop(backend_handle);
            self.block_on_handle(first_field)?;
        }

        // Decode to the same surface as the first field picture.
        let first_va_handle = first_field.handle();
        let va_picture = first_va_handle
            .picture()
            .expect("no valid backend handle after blocking on it");
        self.current_picture = Some(VaPicture::new_from_same_surface(timestamp, va_picture));

        Ok(())
    }

    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any {
        &self.test_params
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

    use libva::Display;

    use crate::decoders::h264::backends::vaapi::TestParams;
    use crate::decoders::h264::backends::StatelessDecoderBackend;
    use crate::decoders::h264::decoder::tests::process_ready_frames;
    use crate::decoders::h264::decoder::tests::run_decoding_loop;
    use crate::decoders::h264::decoder::Decoder;
    use crate::decoders::BlockingMode;
    use crate::decoders::DecodedHandle;
    use crate::decoders::DynHandle;
    use crate::utils::vaapi::DecodedHandle as VADecodedHandle;

    fn get_test_params(
        backend: &dyn StatelessDecoderBackend<Handle = VADecodedHandle>,
    ) -> &TestParams {
        backend
            .get_test_params()
            .downcast_ref::<TestParams>()
            .unwrap()
    }

    fn process_handle(
        handle: &VADecodedHandle,
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
    fn test_16x16_progressive_i() {
        /// This test is the same as
        /// h264::decoders::tests::test_16x16_progressive_i, but with an actual
        /// backend to test whether the backend specific logic works and the
        /// produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/16x16-I.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            // CRC from the GStreamer decoder, should be good enough for us for now.
            let mut expected_crcs = HashSet::from(["2737596b"]);

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let _params = get_test_params(decoder.backend());

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_16x16_progressive_i_and_p() {
        /// This test is the same as
        /// h264::decoders::tests::test_16x16_progressive_i_and_p, but with an
        /// actual backend to test whether the backend specific logic works and
        /// the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/16x16-I-P.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            let mut expected_crcs = HashSet::from(["1d0295c6", "2563d883"]);

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                // Contains the VA-API params used to decode the picture. Useful
                // if we want to write assertions against any particular value
                // used therein.
                process_ready_frames(decoder, &mut |decoder, handle| {
                    let _params = get_test_params(decoder.backend());
                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_16x16_progressive_i_p_b_p() {
        /// This test is the same as
        /// h264::decoders::tests::test_16x16_progressive_i_p_b_p, but with an
        /// actual backend to test whether the backend specific logic works and
        /// the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/16x16-I-P-B-P.h264");
        const STREAM_CRCS: &str = include_str!("../test_data/16x16-I-P-B-P.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = get_test_params(decoder.backend());

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_16x16_progressive_i_p_b_p_high() {
        /// This test is the same as
        /// h264::decoders::tests::test_16x16_progressive_i_p_b_p_high, but with
        /// an actual backend to test whether the backend specific logic works
        /// and the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/16x16-I-P-B-P-high.h264");
        const STREAM_CRCS: &str = include_str!("../test_data/16x16-I-P-B-P-high.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = get_test_params(decoder.backend());

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_interlaced_h264() {
        /// This test is the same as
        /// h264::decoders::tests::test_25fps_interlaced_h264, but with an
        /// actual backend to test whether the backend specific logic works and
        /// the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/test-25fps-interlaced.h264");
        const STREAM_CRCS: &str = include_str!("../test_data/test-25fps-interlaced.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = get_test_params(decoder.backend());

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }

    #[test]
    // Ignore this test by default as it requires libva-compatible hardware.
    #[ignore]
    fn test_25fps_h264() {
        /// This test is the same as h264::decoders::tests::test_25fps_h264, but
        /// with an actual backend to test whether the backend specific logic
        /// works and the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../test_data/test-25fps.h264");
        const STREAM_CRCS: &str = include_str!("../test_data/test-25fps.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;
            let display = Display::open().unwrap();
            let mut decoder = Decoder::new_vaapi(display, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = get_test_params(decoder.backend());

                    process_handle(handle, false, Some(&mut expected_crcs), frame_num);

                    frame_num += 1;
                });
            });

            assert!(
                expected_crcs.is_empty(),
                "Some CRCs were not produced by the decoder: {:?}",
                expected_crcs
            );
        }
    }
}

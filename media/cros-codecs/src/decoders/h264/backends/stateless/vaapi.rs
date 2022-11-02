// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Context as AnyhowContext;
use anyhow::Result;
use libva::BufferType;
use libva::IQMatrix;
use libva::IQMatrixBufferH264;
use libva::Picture as VaPicture;
use libva::PictureEnd;
use libva::PictureNew;
use libva::PictureParameter;
use libva::PictureParameterBufferH264;
use libva::SliceParameter;
use libva::UsageHint;
use log::debug;

use crate::decoders::h264::backends::stateless::BlockingMode;
use crate::decoders::h264::backends::stateless::ContainedPicture;
use crate::decoders::h264::backends::stateless::DecodedHandle;
use crate::decoders::h264::backends::stateless::Result as StatelessBackendResult;
use crate::decoders::h264::backends::stateless::StatelessDecoderBackend;
use crate::decoders::h264::decoder::Decoder;
use crate::decoders::h264::decoder::Profile;
use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::parser::Pps;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::Field;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::h264::picture::Reference;
use crate::decoders::Error as DecoderError;
use crate::decoders::Result as DecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::VideoDecoderBackend;
use crate::utils;
use crate::utils::vaapi::DecodedHandle as VADecodedHandle;
use crate::utils::vaapi::FormatMap;
use crate::utils::vaapi::GenericBackendHandle;
use crate::utils::vaapi::GenericBackendHandleInner;
use crate::utils::vaapi::StreamMetadataState;
use crate::utils::vaapi::SurfacePoolHandle;
use crate::DecodedFormat;
use crate::Resolution;

/// Resolves to the type used as Handle by the backend.
type AssociatedHandle = <Backend as StatelessDecoderBackend>::Handle;

/// Resolves to the type used as BackendHandle by the backend.
type AssociatedBackendHandle = <AssociatedHandle as DecodedHandle>::BackendHandle;

/// Keeps track of where the backend is in the negotiation process.
#[derive(Clone, Debug)]
enum NegotiationStatus {
    NonNegotiated,
    Possible { sps: Box<Sps>, dpb_size: usize },
    Negotiated,
}

impl Default for NegotiationStatus {
    fn default() -> Self {
        NegotiationStatus::NonNegotiated
    }
}

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

/// A type that keeps track of a pending decoding operation. The backend can
/// complete the job by either querying its status with VA-API or by blocking on
/// it at some point in the future.
///
/// Once the backend is sure that the operation went through, it can assign the
/// handle to `h264_picture` and dequeue this object from the pending queue.
struct PendingJob<BackendHandle> {
    /// A picture that was already sent to VA-API. It is unclear whether it has
    /// been decoded yet because we have been asked not to block on it.
    va_picture: VaPicture<PictureEnd>,
    /// A handle to the picture passed in by the H264 decoder. It has no handle
    /// backing it yet, as we cannot be sure that the decoding operation went
    /// through.
    h264_picture: ContainedPicture<BackendHandle>,
}

/// H.264 stateless decoder backend for VA-API.
pub struct Backend {
    /// The metadata state. Updated whenever the decoder reads new data from the stream.
    metadata_state: StreamMetadataState,
    /// The current picture being worked on.
    current_picture: Option<VaPicture<PictureNew>>,
    /// The FIFO for all pending pictures, in the order they were submitted.
    pending_jobs: VecDeque<PendingJob<AssociatedBackendHandle>>,
    /// The image formats we can decode into.
    image_formats: Rc<Vec<libva::VAImageFormat>>,
    /// The number of allocated surfaces.
    num_allocated_surfaces: usize,
    /// The negotiation status
    negotiation_status: NegotiationStatus,

    #[cfg(test)]
    /// Test params. Saves the metadata sent to VA-API for the purposes of
    /// testing.
    test_params: TestParams,
}

impl Backend {
    /// Creates a new codec backend for H.264.
    pub fn new(display: Rc<libva::Display>) -> Result<Self> {
        let image_formats = Rc::new(display.query_image_formats()?);

        Ok(Self {
            metadata_state: StreamMetadataState::Unparsed { display },
            current_picture: Default::default(),
            pending_jobs: Default::default(),
            num_allocated_surfaces: Default::default(),
            negotiation_status: Default::default(),
            image_formats,

            #[cfg(test)]
            test_params: Default::default(),
        })
    }

    /// Initializes or reinitializes the codec state.
    fn open(
        &mut self,
        sps: &Sps,
        max_dpb_frames: usize,
        format_map: Option<&FormatMap>,
    ) -> Result<()> {
        let display = self.metadata_state.display();

        let profile_idc = sps.profile_idc();
        let profile = Profile::n(profile_idc)
            .with_context(|| format!("Invalid profile_idc {:?}", profile_idc))?;
        let va_profile = Backend::get_profile(profile, sps.constraint_set0_flag())?;

        let rt_format =
            Backend::get_rt_fmt(sps.bit_depth_chroma_minus8() + 8, sps.chroma_format_idc())?;

        let frame_w = sps.width();
        let frame_h = sps.height();

        let attrs = vec![libva::VAConfigAttrib {
            type_: libva::VAConfigAttribType::VAConfigAttribRTFormat,
            value: rt_format,
        }];

        let config =
            display.create_config(attrs, va_profile, libva::VAEntrypoint::VAEntrypointVLD)?;

        let format_map = if let Some(format_map) = format_map {
            format_map
        } else {
            // Pick the first one that fits
            utils::vaapi::FORMAT_MAP
                .iter()
                .find(|&map| map.rt_format == rt_format)
                .ok_or(anyhow!("Unsupported format {}", rt_format))?
        };

        let map_format = self
            .image_formats
            .iter()
            .find(|f| f.fourcc == format_map.va_fourcc)
            .cloned()
            .unwrap();

        let num_surfaces = max_dpb_frames + 4;

        let surfaces = display.create_surfaces(
            rt_format,
            Some(map_format.fourcc),
            frame_w,
            frame_h,
            Some(UsageHint::USAGE_HINT_DECODER),
            num_surfaces as u32,
        )?;
        self.num_allocated_surfaces = num_surfaces;

        let context = display.create_context(
            &config,
            i32::try_from(frame_w)?,
            i32::try_from(frame_h)?,
            Some(&surfaces),
            true,
        )?;

        let coded_resolution = Resolution {
            width: frame_w,
            height: frame_h,
        };

        let visible_rect = sps.visible_rectangle();

        let display_resolution = Resolution {
            width: visible_rect.max.x - visible_rect.min.x,
            height: visible_rect.max.y - visible_rect.min.y,
        };

        let surface_pool = SurfacePoolHandle::new(surfaces, coded_resolution);

        self.metadata_state = StreamMetadataState::Parsed {
            context,
            config,
            surface_pool,
            coded_resolution,
            display_resolution,
            map_format: Rc::new(map_format),
            rt_format,
            profile: va_profile,
        };

        Ok(())
    }

    fn get_profile(profile: Profile, constraint_set0_flag: bool) -> Result<libva::VAProfile::Type> {
        match profile {
            Profile::Baseline => {
                if constraint_set0_flag {
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

    fn get_rt_fmt(bit_depth_luma: u8, chroma_format_idc: u8) -> Result<u32> {
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

    /// Gets the VASurfaceID for the given `picture`.
    fn surface_id(picture: &H264Picture<AssociatedBackendHandle>) -> libva::VASurfaceID {
        if picture.nonexisting {
            return libva::constants::VA_INVALID_SURFACE;
        }

        let va_picture = &picture.backend_handle.as_ref().unwrap().inner;

        match va_picture {
            GenericBackendHandleInner::Ready { picture, .. } => picture.surface().id(),
            GenericBackendHandleInner::Pending(id) => *id,
        }
    }

    /// Fills the internal `va_pic` picture parameter with data from `h264_pic`
    fn fill_va_h264_pic(
        h264_pic: &H264Picture<AssociatedBackendHandle>,
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
            Decoder::<AssociatedHandle>::get_raster_from_zigzag_4x4(
                pps.scaling_lists_4x4()[i],
                &mut scaling_list4x4[i],
            );
        });

        (0..2).for_each(|i| {
            Decoder::<AssociatedHandle>::get_raster_from_zigzag_8x8(
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
        current_picture: &H264Picture<AssociatedBackendHandle>,
        current_surface_id: libva::VASurfaceID,
        dpb: &Dpb<AssociatedHandle>,
        sps: &Sps,
        pps: &Pps,
    ) -> Result<BufferType> {
        let curr_pic = Backend::fill_va_h264_pic(current_picture, current_surface_id, false);

        let mut refs = vec![];
        let mut va_refs = vec![];

        dpb.get_short_term_refs(&mut refs);
        refs.retain(|handle| {
            let pic = handle.picture();
            !pic.nonexisting && !pic.is_second_field()
        });

        for handle in &refs {
            let ref_pic = handle.picture();
            let surface_id = Backend::surface_id(&ref_pic);
            let pic = Backend::fill_va_h264_pic(&ref_pic, surface_id, true);
            va_refs.push(pic);
        }

        refs.clear();

        dpb.get_long_term_refs(&mut refs);
        refs.retain(|handle| {
            let pic = handle.picture();
            !pic.is_second_field()
        });

        for handle in &refs {
            let ref_pic = handle.picture();
            let surface_id = Backend::surface_id(&ref_pic);
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
            (sps.level_idc() > 31) as u32, /* see A.3.3.2 */
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

    fn build_va_decoded_handle(
        &self,
        picture: &ContainedPicture<AssociatedBackendHandle>,
    ) -> Result<AssociatedHandle> {
        Ok(VADecodedHandle::new(
            Rc::clone(picture),
            self.metadata_state.coded_resolution()?,
            self.metadata_state.surface_pool()?,
        ))
    }

    fn fill_ref_pic_list(ref_list_x: &[AssociatedHandle]) -> [libva::PictureH264; 32] {
        let mut va_pics = vec![];

        for handle in ref_list_x {
            let pic = handle.picture();
            let surface_id = Backend::surface_id(&pic);
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
        ref_list_0: &[AssociatedHandle],
        ref_list_1: &[AssociatedHandle],
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
    fn num_resources_total(&self) -> usize {
        self.num_allocated_surfaces
    }

    fn num_resources_left(&self) -> usize {
        match self.metadata_state.surface_pool() {
            Ok(pool) => pool.num_surfaces_left(),
            Err(_) => 0,
        }
    }

    fn format(&self) -> Option<DecodedFormat> {
        let map_format = self.metadata_state.map_format().ok()?;
        DecodedFormat::try_from(map_format.as_ref()).ok()
    }

    fn try_format(&mut self, format: DecodedFormat) -> DecoderResult<()> {
        let (sps, dpb_size) = match &self.negotiation_status {
            NegotiationStatus::Possible { sps, dpb_size } => (sps, dpb_size),
            _ => {
                return Err(DecoderError::StatelessBackendError(
                    StatelessBackendError::NegotiationFailed(anyhow!(
                        "Negotiation is not possible at this stage {:?}",
                        self.negotiation_status
                    )),
                ))
            }
        };

        let supported_formats_for_stream = self.supported_formats_for_stream()?;

        if supported_formats_for_stream.contains(&format) {
            let map_format = utils::vaapi::FORMAT_MAP
                .iter()
                .find(|&map| map.decoded_format == format)
                .unwrap();

            let sps = sps.clone();
            let dpb_size = *dpb_size;
            self.open(&sps, dpb_size, Some(map_format))?;

            Ok(())
        } else {
            Err(DecoderError::StatelessBackendError(
                StatelessBackendError::NegotiationFailed(anyhow!(
                    "Format {:?} is unsupported.",
                    format
                )),
            ))
        }
    }

    fn supported_formats_for_stream(&self) -> DecoderResult<HashSet<DecodedFormat>> {
        let rt_format = self.metadata_state.rt_format()?;
        let image_formats = &self.image_formats;
        let display = self.metadata_state.display();
        let profile = self.metadata_state.profile()?;

        let formats = utils::vaapi::supported_formats_for_rt_format(
            display,
            rt_format,
            profile,
            libva::VAEntrypoint::VAEntrypointVLD,
            image_formats,
        )?;

        Ok(formats.into_iter().map(|f| f.decoded_format).collect())
    }

    fn coded_resolution(&self) -> Option<Resolution> {
        self.metadata_state.coded_resolution().ok()
    }

    fn display_resolution(&self) -> Option<Resolution> {
        self.metadata_state.display_resolution().ok()
    }
}

impl StatelessDecoderBackend for Backend {
    type Handle = VADecodedHandle<H264Picture<GenericBackendHandle>>;

    fn new_sequence(&mut self, sps: &Sps, dpb_size: usize) -> StatelessBackendResult<()> {
        self.negotiation_status = NegotiationStatus::Possible {
            sps: Box::new(sps.clone()),
            dpb_size,
        };

        self.open(sps, dpb_size, None)
            .map_err(StatelessBackendError::Other)
    }

    fn handle_picture(
        &mut self,
        picture: &H264Picture<AssociatedBackendHandle>,
        timestamp: u64,
        sps: &Sps,
        pps: &Pps,
        dpb: &Dpb<Self::Handle>,
        slice: &Slice<&dyn AsRef<[u8]>>,
    ) -> StatelessBackendResult<()> {
        debug!(
            "Va-API backend: handle_picture for timestamp {:?}",
            timestamp
        );

        self.negotiation_status = NegotiationStatus::Negotiated;

        let context = self.metadata_state.context()?;

        let va_pic = self.current_picture.as_mut().unwrap();
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
        slice: &Slice<&dyn AsRef<[u8]>>,
        sps: &Sps,
        pps: &Pps,
        _: &Dpb<Self::Handle>,
        ref_pic_list0: &[AssociatedHandle],
        ref_pic_list1: &[AssociatedHandle],
    ) -> StatelessBackendResult<()> {
        let context = self.metadata_state.context()?;

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

        let cur_va_pic = self.current_picture.as_mut().unwrap();
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
        picture: H264Picture<AssociatedBackendHandle>,
        block: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        let current_picture = self.current_picture.take().unwrap();
        let surface_id = current_picture.surface().id();
        let current_picture = current_picture.begin()?.render()?.end()?;

        let picture = Rc::new(RefCell::new(picture));

        if block {
            // Block waiting for the decode operation to complete.
            let current_picture = current_picture.sync()?;
            let map_format = self.metadata_state.map_format()?;

            let backend_handle = GenericBackendHandle::new(GenericBackendHandleInner::Ready {
                context: self.metadata_state.context()?,
                map_format: Rc::clone(map_format),
                picture: current_picture,
                display_resolution: self.metadata_state.display_resolution()?,
            });

            picture.borrow_mut().backend_handle = Some(backend_handle);
        } else {
            // Append to our queue of pending jobs
            let pending_job = PendingJob {
                va_picture: current_picture,
                h264_picture: Rc::clone(&picture),
            };

            self.pending_jobs.push_back(pending_job);

            picture.borrow_mut().backend_handle = Some(GenericBackendHandle::new(
                GenericBackendHandleInner::Pending(surface_id),
            ));
        }

        self.build_va_decoded_handle(&picture)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
    }

    fn poll(
        &mut self,
        blocking_mode: BlockingMode,
    ) -> StatelessBackendResult<VecDeque<Self::Handle>> {
        let mut completed = VecDeque::new();
        let candidates = self.pending_jobs.drain(..).collect::<VecDeque<_>>();

        for job in candidates {
            if matches!(blocking_mode, BlockingMode::NonBlocking) {
                let status = job.va_picture.query_status()?;
                if status != libva::VASurfaceStatus::VASurfaceReady {
                    self.pending_jobs.push_back(job);
                    continue;
                }
            }

            let current_picture = job.va_picture.sync()?;

            let map_format = self.metadata_state.map_format()?;

            let backend_handle = GenericBackendHandle::new(GenericBackendHandleInner::Ready {
                context: self.metadata_state.context()?,
                map_format: Rc::clone(map_format),
                picture: current_picture,
                display_resolution: self.metadata_state.display_resolution()?,
            });

            job.h264_picture.borrow_mut().backend_handle = Some(backend_handle);

            completed.push_back(job.h264_picture);
        }

        let completed = completed.into_iter().map(|picture| {
            self.build_va_decoded_handle(&picture)
                .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
        });

        completed.collect::<Result<VecDeque<_>, StatelessBackendError>>()
    }

    fn new_handle(
        &mut self,
        picture: ContainedPicture<AssociatedBackendHandle>,
    ) -> StatelessBackendResult<Self::Handle> {
        self.build_va_decoded_handle(&picture)
            .map_err(|e| StatelessBackendError::Other(anyhow!(e)))
    }

    fn new_split_picture(
        &mut self,
        split_picture: ContainedPicture<AssociatedBackendHandle>,
        new_picture: ContainedPicture<AssociatedBackendHandle>,
    ) -> StatelessBackendResult<()> {
        let backend_handle = split_picture
            .borrow()
            .backend_handle
            .as_ref()
            .map(|backend_handle| match &backend_handle.inner {
                GenericBackendHandleInner::Ready {
                    context,
                    map_format,
                    picture,
                    display_resolution: resolution,
                } => GenericBackendHandle::new(GenericBackendHandleInner::Ready {
                    context: Rc::clone(context),
                    map_format: Rc::clone(map_format),
                    picture: VaPicture::new_from_same_surface(picture.timestamp(), picture),
                    display_resolution: *resolution,
                }),
                GenericBackendHandleInner::Pending(id) => {
                    GenericBackendHandle::new(GenericBackendHandleInner::Pending(*id))
                }
            });

        new_picture.borrow_mut().backend_handle = backend_handle;

        Ok(())
    }

    fn new_picture(
        &mut self,
        _: &H264Picture<super::AsBackendHandle<Self::Handle>>,
        timestamp: u64,
    ) -> StatelessBackendResult<()> {
        let context = self.metadata_state.context()?;

        let surface = self
            .metadata_state
            .get_surface()?
            .ok_or(StatelessBackendError::OutOfResources)?;

        let va_pic = VaPicture::new(timestamp, Rc::clone(&context), surface);

        self.current_picture = Some(va_pic);

        Ok(())
    }

    fn new_field_picture(
        &mut self,
        _: &H264Picture<super::AsBackendHandle<Self::Handle>>,
        timestamp: u64,
        first_field: &Self::Handle,
    ) -> StatelessBackendResult<()> {
        let first_va_picture = first_field.picture();
        let backend_handle = first_va_picture.backend_handle.as_ref().unwrap();

        if matches!(backend_handle.inner, GenericBackendHandleInner::Pending(_)) {
            drop(first_va_picture);
            self.block_on_handle(first_field)?;
        }

        let first_va_picture = first_field.picture();
        let backend_handle = first_va_picture.backend_handle.as_ref().unwrap();
        let backend_handle = match &backend_handle.inner {
            GenericBackendHandleInner::Ready { picture, .. } => picture,
            GenericBackendHandleInner::Pending(_) => {
                panic!("No valid backend handle after blocking on it")
            }
        };

        // Decode to the same surface as the first field picture.
        self.current_picture = Some(VaPicture::new_from_same_surface(timestamp, backend_handle));

        Ok(())
    }

    fn handle_is_ready(&self, handle: &Self::Handle) -> bool {
        match &handle.picture().backend_handle {
            Some(backend_handle) => {
                matches!(
                    backend_handle.inner,
                    GenericBackendHandleInner::Ready { .. }
                )
            }
            None => true,
        }
    }

    fn as_video_decoder_backend_mut(&mut self) -> &mut dyn VideoDecoderBackend {
        self
    }

    fn as_video_decoder_backend(&self) -> &dyn VideoDecoderBackend {
        self
    }

    fn block_on_handle(&mut self, handle: &Self::Handle) -> StatelessBackendResult<()> {
        for i in 0..self.pending_jobs.len() {
            // Remove from the queue in order.
            let job = &self.pending_jobs[i];

            if H264Picture::same(&job.h264_picture, handle.picture_container()) {
                let job = self.pending_jobs.remove(i).unwrap();

                let current_picture = job.va_picture.sync()?;

                let map_format = self.metadata_state.map_format()?;

                let backend_handle = GenericBackendHandle::new(GenericBackendHandleInner::Ready {
                    context: self.metadata_state.context()?,
                    map_format: Rc::clone(map_format),
                    picture: current_picture,
                    display_resolution: self.metadata_state.display_resolution()?,
                });

                job.h264_picture.borrow_mut().backend_handle = Some(backend_handle);

                return Ok(());
            }
        }

        Err(StatelessBackendError::Other(anyhow!(
            "Asked to block on a pending job that doesn't exist"
        )))
    }
}

impl DecodedHandle for VADecodedHandle<H264Picture<GenericBackendHandle>> {
    type CodecData = PictureData<Self::BackendHandle>;
    type BackendHandle = GenericBackendHandle;

    fn picture_container(&self) -> &ContainedPicture<Self::BackendHandle> {
        self.inner()
    }

    fn display_resolution(&self) -> Resolution {
        self.picture().display_resolution
    }

    fn display_order(&self) -> Option<u64> {
        self.display_order
    }

    fn set_display_order(&mut self, display_order: u64) {
        self.display_order = Some(display_order)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::rc::Rc;

    use libva::Display;

    use crate::decoders::h264::backends;
    use crate::decoders::h264::backends::stateless::vaapi::AssociatedHandle;
    use crate::decoders::h264::backends::stateless::vaapi::Backend;
    use crate::decoders::h264::backends::stateless::BlockingMode;
    use crate::decoders::h264::backends::stateless::DecodedHandle;
    use crate::decoders::h264::backends::stateless::StatelessDecoderBackend;
    use crate::decoders::h264::decoder::tests::process_ready_frames;
    use crate::decoders::h264::decoder::tests::run_decoding_loop;
    use crate::decoders::h264::decoder::Decoder;
    use crate::decoders::DynPicture;

    fn as_vaapi_backend(
        backend: &dyn StatelessDecoderBackend<Handle = AssociatedHandle>,
    ) -> &backends::stateless::vaapi::Backend {
        backend
            .downcast_ref::<backends::stateless::vaapi::Backend>()
            .unwrap()
    }

    fn process_handle(
        handle: &AssociatedHandle,
        dump_yuv: bool,
        expected_crcs: Option<&mut HashSet<&str>>,
        frame_num: i32,
    ) {
        let mut picture = handle.picture_mut();
        let backend_handle = picture.dyn_mappable_handle_mut();

        let resolution = backend_handle.mapped_resolution().unwrap();

        let mut nv12 = vec![0; resolution.width as usize * resolution.height as usize * 3 / 2];

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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/16x16-I.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());

            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            // CRC from the GStreamer decoder, should be good enough for us for now.
            let mut expected_crcs = HashSet::from(["2737596b"]);

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the params used to decode the picture. Useful if we want to
                    // write assertions against any particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/16x16-I-P.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            let mut expected_crcs = HashSet::from(["1d0295c6", "2563d883"]);

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                // Contains the VA-API params used to decode the picture. Useful
                // if we want to write assertions against any particular value
                // used therein.
                process_ready_frames(decoder, &mut |decoder, handle| {
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;
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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/16x16-I-P-B-P.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/16x16-I-P-B-P.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/16x16-I-P-B-P-high.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/16x16-I-P-B-P-high.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
    fn test_interlaced_kodi_1080i() {
        /// This test is the same as
        /// h264::decoders::tests::test_interlaced_kodi_1080i, but with an
        /// actual backend to test whether the backend specific logic works and
        /// the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/test-kodi-1080i-25-H264.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/test-kodi-1080i-25-H264.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();

            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
    fn test_kodi_1080p() {
        /// This test is the same as
        /// h264::decoders::tests::test_interlaced_kodi_1080p, but with an
        /// actual backend to test whether the backend specific logic works and
        /// the produced CRCs match their expected values.
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/FPS_test_1080p24_l4_1.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/FPS_test_1080p24_l4_1.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/test-25fps-interlaced.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/test-25fps-interlaced.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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
        const TEST_STREAM: &[u8] = include_bytes!("../../test_data/test-25fps.h264");
        const STREAM_CRCS: &str = include_str!("../../test_data/test-25fps.h264.crc");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut expected_crcs = STREAM_CRCS.lines().collect::<HashSet<_>>();
            let mut frame_num = 0;

            let display = Rc::new(Display::open().unwrap());
            let backend = Box::new(Backend::new(Rc::clone(&display)).unwrap());
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |decoder, handle| {
                    // Contains the VA-API params used to decode the picture.
                    // Useful if we want to write assertions against any
                    // particular value used therein.
                    let _params = &as_vaapi_backend(decoder.backend()).test_params;

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

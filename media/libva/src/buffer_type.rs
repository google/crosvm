// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::bindings;

/// An abstraction over VA BufferTypes
pub enum BufferType {
    /// An abstraction over VAPictureParameterBufferType. Needed for MPEG2, VP8, VP9, H264
    PictureParameter(PictureParameter),
    /// An abstraction over VASliceParameterBufferType. Needed for MPEG2, VP8, VP9, H264
    SliceParameter(SliceParameter),
    /// An abstraction over VAIQMatrixBufferType. Needed for VP8, H264
    IQMatrix(IQMatrix),
    /// An abstraction over VAProbabilityDataBuffeTyper. Needed for VP8
    Probability(ProbabilityDataBufferVP8),
    /// An abstraction over VASliceDataBufferType. Needed for VP9, H264
    SliceData(Vec<u8>),
}

impl BufferType {
    /// Returns the inner FFI buffer type.
    pub(crate) fn inner(&self) -> bindings::VABufferType::Type {
        match self {
            BufferType::PictureParameter(_) => bindings::VABufferType::VAPictureParameterBufferType,
            BufferType::SliceParameter(_) => bindings::VABufferType::VASliceParameterBufferType,
            BufferType::IQMatrix(_) => bindings::VABufferType::VAIQMatrixBufferType,
            BufferType::Probability(_) => bindings::VABufferType::VAProbabilityBufferType,
            BufferType::SliceData { .. } => bindings::VABufferType::VASliceDataBufferType,
        }
    }
}

/// Wrapper over the `picture_coding_extension` bindgen field in VAPictureParameterBufferMPEG2
pub struct MPEG2PictureCodingExtension(bindings::_VAPictureParameterBufferMPEG2__bindgen_ty_1);

impl MPEG2PictureCodingExtension {
    /// Creates the bindgen field
    pub fn new(
        intra_dc_precision: u32,
        picture_structure: u32,
        top_field_first: u32,
        frame_pred_frame_dct: u32,
        concealment_motion_vectors: u32,
        q_scale_type: u32,
        intra_vlc_format: u32,
        alternate_scan: u32,
        repeat_first_field: u32,
        progressive_frame: u32,
        is_first_field: u32,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VAPictureParameterBufferMPEG2__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                intra_dc_precision,
                picture_structure,
                top_field_first,
                frame_pred_frame_dct,
                concealment_motion_vectors,
                q_scale_type,
                intra_vlc_format,
                alternate_scan,
                repeat_first_field,
                progressive_frame,
                is_first_field,
            );

        Self(bindings::_VAPictureParameterBufferMPEG2__bindgen_ty_1 {
            bits: bindings::_VAPictureParameterBufferMPEG2__bindgen_ty_1__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
                __bindgen_padding_0: Default::default(),
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::_VAPictureParameterBufferMPEG2__bindgen_ty_1 {
        &self.0
    }
}

/// Wrapper over the PictureParameterBufferMPEG2 FFI type.
pub struct PictureParameterBufferMPEG2(Box<bindings::VAPictureParameterBufferMPEG2>);

impl PictureParameterBufferMPEG2 {
    /// Creates the wrapper
    pub fn new(
        horizontal_size: u16,
        vertical_size: u16,
        forward_reference_picture: bindings::VASurfaceID,
        backward_reference_picture: bindings::VASurfaceID,
        picture_coding_type: i32,
        f_code: i32,
        picture_coding_extension: &MPEG2PictureCodingExtension,
    ) -> Self {
        let picture_coding_extension = picture_coding_extension.0;

        Self(Box::new(bindings::VAPictureParameterBufferMPEG2 {
            horizontal_size,
            vertical_size,
            forward_reference_picture,
            backward_reference_picture,
            picture_coding_type,
            f_code,
            picture_coding_extension,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAPictureParameterBufferMPEG2 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::VAPictureParameterBufferMPEG2 {
        self.0.as_ref()
    }
}

/// Wrapper over the `pic_fields` bindgen field in VAPictureParameterBufferVP8
pub struct VP8PicFields(bindings::_VAPictureParameterBufferVP8__bindgen_ty_1);

impl VP8PicFields {
    /// Creates the bindgen field
    pub fn new(
        key_frame: u32,
        version: u32,
        segmentation_enabled: u32,
        update_mb_segmentation_map: u32,
        update_segment_feature_data: u32,
        filter_type: u32,
        sharpness_level: u32,
        loop_filter_adj_enable: u32,
        mode_ref_lf_delta_update: u32,
        sign_bias_golden: u32,
        sign_bias_alternate: u32,
        mb_no_coeff_skip: u32,
        loop_filter_disable: u32,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VAPictureParameterBufferVP8__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                key_frame,
                version,
                segmentation_enabled,
                update_mb_segmentation_map,
                update_segment_feature_data,
                filter_type,
                sharpness_level,
                loop_filter_adj_enable,
                mode_ref_lf_delta_update,
                sign_bias_golden,
                sign_bias_alternate,
                mb_no_coeff_skip,
                loop_filter_disable,
            );

        Self(bindings::_VAPictureParameterBufferVP8__bindgen_ty_1 {
            bits: bindings::_VAPictureParameterBufferVP8__bindgen_ty_1__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
                __bindgen_padding_0: Default::default(),
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::_VAPictureParameterBufferVP8__bindgen_ty_1 {
        &self.0
    }
}

/// Wrapper over the VABoolCoderContextVPX FFI type
pub struct BoolCoderContextVPX(bindings::VABoolCoderContextVPX);

impl BoolCoderContextVPX {
    /// Creates the wrapper
    pub fn new(range: u8, value: u8, count: u8) -> Self {
        Self(bindings::VABoolCoderContextVPX {
            range,
            value,
            count,
        })
    }
}

/// Wrapper over the PictureParameterBufferVP8 FFI type
pub struct PictureParameterBufferVP8(Box<bindings::VAPictureParameterBufferVP8>);

impl PictureParameterBufferVP8 {
    /// Creates the wrapper
    pub fn new(
        frame_width: u32,
        frame_height: u32,
        last_ref_frame: bindings::VASurfaceID,
        golden_ref_frame: bindings::VASurfaceID,
        alt_ref_frame: bindings::VASurfaceID,
        pic_fields: &VP8PicFields,
        mb_segment_tree_probs: [u8; 3usize],
        loop_filter_level: [u8; 4usize],
        loop_filter_deltas_ref_frame: [i8; 4usize],
        loop_filter_deltas_mode: [i8; 4usize],
        prob_skip_false: u8,
        prob_intra: u8,
        prob_last: u8,
        prob_gf: u8,
        y_mode_probs: [u8; 4usize],
        uv_mode_probs: [u8; 3usize],
        mv_probs: [[u8; 19usize]; 2usize],
        bool_coder_ctx: &BoolCoderContextVPX,
    ) -> Self {
        let pic_fields = pic_fields.0;
        let bool_coder_ctx = bool_coder_ctx.0;

        Self(Box::new(bindings::VAPictureParameterBufferVP8 {
            frame_width,
            frame_height,
            last_ref_frame,
            golden_ref_frame,
            alt_ref_frame,
            out_of_loop_frame: bindings::constants::VA_INVALID_SURFACE,
            pic_fields,
            mb_segment_tree_probs,
            loop_filter_level,
            loop_filter_deltas_ref_frame,
            loop_filter_deltas_mode,
            prob_skip_false,
            prob_intra,
            prob_last,
            prob_gf,
            y_mode_probs,
            uv_mode_probs,
            mv_probs,
            bool_coder_ctx,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAPictureParameterBufferVP8 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAPictureParameterBufferVP8 {
        self.0.as_ref()
    }
}

/// Wrapper over the `pic_fields` bindgen field in VAPictureParameterBufferVP9
pub struct VP9PicFields(bindings::_VADecPictureParameterBufferVP9__bindgen_ty_1);

impl VP9PicFields {
    /// Creates the bindgen field
    pub fn new(
        subsampling_x: u32,
        subsampling_y: u32,
        frame_type: u32,
        show_frame: u32,
        error_resilient_mode: u32,
        intra_only: u32,
        allow_high_precision_mv: u32,
        mcomp_filter_type: u32,
        frame_parallel_decoding_mode: u32,
        reset_frame_context: u32,
        refresh_frame_context: u32,
        frame_context_idx: u32,
        segmentation_enabled: u32,
        segmentation_temporal_update: u32,
        segmentation_update_map: u32,
        last_ref_frame: u32,
        last_ref_frame_sign_bias: u32,
        golden_ref_frame: u32,
        golden_ref_frame_sign_bias: u32,
        alt_ref_frame: u32,
        alt_ref_frame_sign_bias: u32,
        lossless_flag: u32,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VADecPictureParameterBufferVP9__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                subsampling_x,
                subsampling_y,
                frame_type,
                show_frame,
                error_resilient_mode,
                intra_only,
                allow_high_precision_mv,
                mcomp_filter_type,
                frame_parallel_decoding_mode,
                reset_frame_context,
                refresh_frame_context,
                frame_context_idx,
                segmentation_enabled,
                segmentation_temporal_update,
                segmentation_update_map,
                last_ref_frame,
                last_ref_frame_sign_bias,
                golden_ref_frame,
                golden_ref_frame_sign_bias,
                alt_ref_frame,
                alt_ref_frame_sign_bias,
                lossless_flag,
            );

        Self(bindings::_VADecPictureParameterBufferVP9__bindgen_ty_1 {
            bits: bindings::_VADecPictureParameterBufferVP9__bindgen_ty_1__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::_VADecPictureParameterBufferVP9__bindgen_ty_1 {
        &self.0
    }
}

/// Wrapper over the PictureParameterBufferVP9 FFI type
pub struct PictureParameterBufferVP9(Box<bindings::VADecPictureParameterBufferVP9>);

impl PictureParameterBufferVP9 {
    /// Creates the wrapper
    pub fn new(
        frame_width: u16,
        frame_height: u16,
        reference_frames: [bindings::VASurfaceID; 8],
        pic_fields: &VP9PicFields,
        filter_level: u8,
        sharpness_level: u8,
        log2_tile_rows: u8,
        log2_tile_columns: u8,
        frame_header_length_in_bytes: u8,
        first_partition_size: u16,
        mb_segment_tree_probs: [u8; 7usize],
        segment_pred_probs: [u8; 3usize],
        profile: u8,
        bit_depth: u8,
    ) -> Self {
        let pic_fields = pic_fields.0;

        Self(Box::new(bindings::VADecPictureParameterBufferVP9 {
            frame_width,
            frame_height,
            reference_frames,
            pic_fields,
            filter_level,
            sharpness_level,
            log2_tile_rows,
            log2_tile_columns,
            frame_header_length_in_bytes,
            first_partition_size,
            mb_segment_tree_probs,
            segment_pred_probs,
            profile,
            bit_depth,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VADecPictureParameterBufferVP9 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VADecPictureParameterBufferVP9 {
        self.0.as_ref()
    }
}

/// Wrapper over the VAPictureH264 FFI type
pub struct PictureH264(bindings::VAPictureH264);

impl PictureH264 {
    /// Creates the wrapper
    pub fn new(
        picture_id: bindings::VASurfaceID,
        frame_idx: u32,
        flags: u32,
        top_field_order_cnt: i32,
        bottom_field_order_cnt: i32,
    ) -> Self {
        Self(bindings::VAPictureH264 {
            picture_id,
            frame_idx,
            flags,
            TopFieldOrderCnt: top_field_order_cnt,
            BottomFieldOrderCnt: bottom_field_order_cnt,
            va_reserved: Default::default(),
        })
    }
}

/// Wrapper over the `seq_fields` bindgen field in VAPictureParameterBufferH264
pub struct H264SeqFields(bindings::_VAPictureParameterBufferH264__bindgen_ty_1);

impl H264SeqFields {
    /// Creates the bindgen field
    pub fn new(
        chroma_format_idc: u32,
        residual_colour_transform_flag: u32,
        gaps_in_frame_num_value_allowed_flag: u32,
        frame_mbs_only_flag: u32,
        mb_adaptive_frame_field_flag: u32,
        direct_8x8_inference_flag: u32,
        min_luma_bi_pred_size8x8: u32,
        log2_max_frame_num_minus4: u32,
        pic_order_cnt_type: u32,
        log2_max_pic_order_cnt_lsb_minus4: u32,
        delta_pic_order_always_zero_flag: u32,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VAPictureParameterBufferH264__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                chroma_format_idc,
                residual_colour_transform_flag,
                gaps_in_frame_num_value_allowed_flag,
                frame_mbs_only_flag,
                mb_adaptive_frame_field_flag,
                direct_8x8_inference_flag,
                min_luma_bi_pred_size8x8,
                log2_max_frame_num_minus4,
                pic_order_cnt_type,
                log2_max_pic_order_cnt_lsb_minus4,
                delta_pic_order_always_zero_flag,
            );

        Self(bindings::_VAPictureParameterBufferH264__bindgen_ty_1 {
            bits: bindings::_VAPictureParameterBufferH264__bindgen_ty_1__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
                __bindgen_padding_0: Default::default(),
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::_VAPictureParameterBufferH264__bindgen_ty_1 {
        &self.0
    }
}

/// Wrapper over the `pic_fields` bindgen field in VAPictureParameterBufferH264
pub struct H264PicFields(bindings::_VAPictureParameterBufferH264__bindgen_ty_2);

impl H264PicFields {
    /// Creates the bindgen field
    pub fn new(
        entropy_coding_mode_flag: u32,
        weighted_pred_flag: u32,
        weighted_bipred_idc: u32,
        transform_8x8_mode_flag: u32,
        field_pic_flag: u32,
        constrained_intra_pred_flag: u32,
        pic_order_present_flag: u32,
        deblocking_filter_control_present_flag: u32,
        redundant_pic_cnt_present_flag: u32,
        reference_pic_flag: u32,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VAPictureParameterBufferH264__bindgen_ty_2__bindgen_ty_1::new_bitfield_1(
                entropy_coding_mode_flag,
                weighted_pred_flag,
                weighted_bipred_idc,
                transform_8x8_mode_flag,
                field_pic_flag,
                constrained_intra_pred_flag,
                pic_order_present_flag,
                deblocking_filter_control_present_flag,
                redundant_pic_cnt_present_flag,
                reference_pic_flag,
            );

        Self(bindings::_VAPictureParameterBufferH264__bindgen_ty_2 {
            bits: bindings::_VAPictureParameterBufferH264__bindgen_ty_2__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
                __bindgen_padding_0: Default::default(),
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::_VAPictureParameterBufferH264__bindgen_ty_2 {
        &self.0
    }
}

/// A wrapper over VAPictureParameterBufferH264 FFI type
pub struct PictureParameterBufferH264(Box<bindings::VAPictureParameterBufferH264>);

impl PictureParameterBufferH264 {
    /// Creates the wrapper
    pub fn new(
        curr_pic: PictureH264,
        reference_frames: [PictureH264; 16],
        picture_width_in_mbs_minus1: u16,
        picture_height_in_mbs_minus1: u16,
        bit_depth_luma_minus8: u8,
        bit_depth_chroma_minus8: u8,
        num_ref_frames: u8,
        seq_fields: &H264SeqFields,
        num_slice_groups_minus1: u8,
        slice_group_map_type: u8,
        slice_group_change_rate_minus1: u16,
        pic_init_qp_minus26: i8,
        pic_init_qs_minus26: i8,
        chroma_qp_index_offset: i8,
        second_chroma_qp_index_offset: i8,
        pic_fields: &H264PicFields,
        frame_num: u16,
    ) -> Self {
        let reference_frames = (0..16usize)
            .map(|i| reference_frames[i].0)
            .collect::<Vec<_>>()
            .try_into()
            // try_into is guaranteed to work because the iterator and target array have the same
            // size.
            .unwrap();

        let seq_fields = seq_fields.0;
        let pic_fields = pic_fields.0;

        Self(Box::new(bindings::VAPictureParameterBufferH264 {
            CurrPic: curr_pic.0,
            ReferenceFrames: reference_frames,
            picture_width_in_mbs_minus1,
            picture_height_in_mbs_minus1,
            bit_depth_luma_minus8,
            bit_depth_chroma_minus8,
            num_ref_frames,
            seq_fields,
            num_slice_groups_minus1,
            slice_group_map_type,
            slice_group_change_rate_minus1,
            pic_init_qp_minus26,
            pic_init_qs_minus26,
            chroma_qp_index_offset,
            second_chroma_qp_index_offset,
            pic_fields,
            frame_num,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAPictureParameterBufferH264 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAPictureParameterBufferH264 {
        self.0.as_ref()
    }
}

/// An abstraction over the PictureParameterBuffer types we support
pub enum PictureParameter {
    /// A wrapper over VAPictureParameterBufferMPEG2
    MPEG2(PictureParameterBufferMPEG2),
    /// A wrapper over VAPictureParameterBufferVP8
    VP8(PictureParameterBufferVP8),
    /// A wrapper over VAPictureParameterBufferVP9
    VP9(PictureParameterBufferVP9),
    /// A wrapper over VAPictureParameterBufferH264
    H264(PictureParameterBufferH264),
}

/// Wrapper over the VASliceParameterBufferMPEG2 FFI type
pub struct SliceParameterBufferMPEG2(Box<bindings::VASliceParameterBufferMPEG2>);

impl SliceParameterBufferMPEG2 {
    /// Creates the wrapper
    pub fn new(
        slice_data_size: u32,
        slice_data_offset: u32,
        slice_data_flag: u32,
        macroblock_offset: u32,
        slice_horizontal_position: u32,
        slice_vertical_position: u32,
        quantiser_scale_code: i32,
        intra_slice_flag: i32,
    ) -> Self {
        Self(Box::new(bindings::VASliceParameterBufferMPEG2 {
            slice_data_size,
            slice_data_offset,
            slice_data_flag,
            macroblock_offset,
            slice_horizontal_position,
            slice_vertical_position,
            quantiser_scale_code,
            intra_slice_flag,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VASliceParameterBufferMPEG2 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VASliceParameterBufferMPEG2 {
        self.0.as_ref()
    }
}

/// An abstraction over the SliceParameterBuffer types we support
pub enum SliceParameter {
    /// A wrapper over VASliceParameterBufferMPEG2
    MPEG2(SliceParameterBufferMPEG2),
    /// A wrapper over VASliceParameterBufferVP8
    VP8(SliceParameterBufferVP8),
    /// A wrapper over VASliceParameterBufferVP9
    VP9(SliceParameterBufferVP9),
    /// A wrapper over VASliceParameterBufferH264
    H264(SliceParameterBufferH264),
}

/// Wrapper over the VASliceParameterBufferVP8 FFI type
pub struct SliceParameterBufferVP8(Box<bindings::VASliceParameterBufferVP8>);

impl SliceParameterBufferVP8 {
    /// Creates the wrapper
    pub fn new(
        slice_data_size: u32,
        slice_data_offset: u32,
        slice_data_flag: u32,
        macroblock_offset: u32,
        num_of_partitions: u8,
        partition_size: [u32; 9usize],
    ) -> Self {
        Self(Box::new(bindings::VASliceParameterBufferVP8 {
            slice_data_size,
            slice_data_offset,
            slice_data_flag,
            macroblock_offset,
            num_of_partitions,
            partition_size,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VASliceParameterBufferVP8 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VASliceParameterBufferVP8 {
        self.0.as_ref()
    }
}

/// Wrapper over the `segment_flags` bindgen field in VASegmentParameterVP9
pub struct VP9SegmentFlags(bindings::_VASegmentParameterVP9__bindgen_ty_1);

impl VP9SegmentFlags {
    /// Creates the wrapper
    pub fn new(
        segment_reference_enabled: u16,
        segment_reference: u16,
        segment_reference_skipped: u16,
    ) -> Self {
        let _bitfield_1 =
            bindings::_VASegmentParameterVP9__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
                segment_reference_enabled,
                segment_reference,
                segment_reference_skipped,
            );

        Self(bindings::_VASegmentParameterVP9__bindgen_ty_1 {
            fields: bindings::_VASegmentParameterVP9__bindgen_ty_1__bindgen_ty_1 {
                _bitfield_align_1: Default::default(),
                _bitfield_1,
                __bindgen_padding_0: Default::default(),
            },
        })
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&mut self) -> &bindings::_VASegmentParameterVP9__bindgen_ty_1 {
        &self.0
    }
}

/// Wrapper over the VASegmentParameterVP9 FFI type
pub struct SegmentParameterVP9(bindings::VASegmentParameterVP9);

impl SegmentParameterVP9 {
    /// Creates the wrapper
    pub fn new(
        segment_flags: &VP9SegmentFlags,
        filter_level: [[u8; 2usize]; 4usize],
        luma_ac_quant_scale: i16,
        luma_dc_quant_scale: i16,
        chroma_ac_quant_scale: i16,
        chroma_dc_quant_scale: i16,
    ) -> Self {
        let segment_flags = segment_flags.0;

        Self(bindings::VASegmentParameterVP9 {
            segment_flags,
            filter_level,
            luma_ac_quant_scale,
            luma_dc_quant_scale,
            chroma_ac_quant_scale,
            chroma_dc_quant_scale,
            va_reserved: Default::default(),
        })
    }
}

/// Wrapper over the VASliceParameterBufferVP9 FFI type
pub struct SliceParameterBufferVP9(Box<bindings::VASliceParameterBufferVP9>);

impl SliceParameterBufferVP9 {
    /// Creates the wrapper
    pub fn new(
        slice_data_size: u32,
        slice_data_offset: u32,
        slice_data_flag: u32,
        seg_param: [SegmentParameterVP9; 8usize],
    ) -> Self {
        let seg_param = seg_param.map(|param| param.0);

        Self(Box::new(bindings::VASliceParameterBufferVP9 {
            slice_data_size,
            slice_data_offset,
            slice_data_flag,
            seg_param,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VASliceParameterBufferVP9 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VASliceParameterBufferVP9 {
        self.0.as_ref()
    }
}

/// Wrapper over the VASliceParameterBufferH264 FFI type
pub struct SliceParameterBufferH264(Box<bindings::VASliceParameterBufferH264>);

impl SliceParameterBufferH264 {
    /// Creates the wrapper
    pub fn new(
        slice_data_size: u32,
        slice_data_offset: u32,
        slice_data_flag: u32,
        slice_data_bit_offset: u16,
        first_mb_in_slice: u16,
        slice_type: u8,
        direct_spatial_mv_pred_flag: u8,
        num_ref_idx_l0_active_minus1: u8,
        num_ref_idx_l1_active_minus1: u8,
        cabac_init_idc: u8,
        slice_qp_delta: i8,
        disable_deblocking_filter_idc: u8,
        slice_alpha_c0_offset_div2: i8,
        slice_beta_offset_div2: i8,
        ref_pic_list_0: [PictureH264; 32usize],
        ref_pic_list_1: [PictureH264; 32usize],
        luma_log2_weight_denom: u8,
        chroma_log2_weight_denom: u8,
        luma_weight_l0_flag: u8,
        luma_weight_l0: [i16; 32usize],
        luma_offset_l0: [i16; 32usize],
        chroma_weight_l0_flag: u8,
        chroma_weight_l0: [[i16; 2usize]; 32usize],
        chroma_offset_l0: [[i16; 2usize]; 32usize],
        luma_weight_l1_flag: u8,
        luma_weight_l1: [i16; 32usize],
        luma_offset_l1: [i16; 32usize],
        chroma_weight_l1_flag: u8,
        chroma_weight_l1: [[i16; 2usize]; 32usize],
        chroma_offset_l1: [[i16; 2usize]; 32usize],
    ) -> Self {
        let ref_pic_list_0 = ref_pic_list_0.map(|pic| pic.0);
        let ref_pic_list_1 = ref_pic_list_1.map(|pic| pic.0);

        Self(Box::new(bindings::VASliceParameterBufferH264 {
            slice_data_size,
            slice_data_offset,
            slice_data_flag,
            slice_data_bit_offset,
            first_mb_in_slice,
            slice_type,
            direct_spatial_mv_pred_flag,
            num_ref_idx_l0_active_minus1,
            num_ref_idx_l1_active_minus1,
            cabac_init_idc,
            slice_qp_delta,
            disable_deblocking_filter_idc,
            slice_alpha_c0_offset_div2,
            slice_beta_offset_div2,
            RefPicList0: ref_pic_list_0,
            RefPicList1: ref_pic_list_1,
            luma_log2_weight_denom,
            chroma_log2_weight_denom,
            luma_weight_l0_flag,
            luma_weight_l0,
            luma_offset_l0,
            chroma_weight_l0_flag,
            chroma_weight_l0,
            chroma_offset_l0,
            luma_weight_l1_flag,
            luma_weight_l1,
            luma_offset_l1,
            chroma_weight_l1_flag,
            chroma_weight_l1,
            chroma_offset_l1,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VASliceParameterBufferH264 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VASliceParameterBufferH264 {
        self.0.as_ref()
    }
}

/// Wrapper over the VAIQMatrixBufferMPEG2 FFI type
pub struct IQMatrixBufferMPEG2(Box<bindings::VAIQMatrixBufferMPEG2>);

impl IQMatrixBufferMPEG2 {
    /// Creates the wrapper
    pub fn new(
        load_intra_quantiser_matrix: i32,
        load_non_intra_quantiser_matrix: i32,
        load_chroma_intra_quantiser_matrix: i32,
        load_chroma_non_intra_quantiser_matrix: i32,
        intra_quantiser_matrix: [u8; 64usize],
        non_intra_quantiser_matrix: [u8; 64usize],
        chroma_intra_quantiser_matrix: [u8; 64usize],
        chroma_non_intra_quantiser_matrix: [u8; 64usize],
    ) -> Self {
        Self(Box::new(bindings::VAIQMatrixBufferMPEG2 {
            load_intra_quantiser_matrix,
            load_non_intra_quantiser_matrix,
            load_chroma_intra_quantiser_matrix,
            load_chroma_non_intra_quantiser_matrix,
            intra_quantiser_matrix,
            non_intra_quantiser_matrix,
            chroma_intra_quantiser_matrix,
            chroma_non_intra_quantiser_matrix,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAIQMatrixBufferMPEG2 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAIQMatrixBufferMPEG2 {
        self.0.as_ref()
    }
}

/// Wrapper over the VAIQMatrixBufferVP8 FFI type
pub struct IQMatrixBufferVP8(Box<bindings::VAIQMatrixBufferVP8>);

impl IQMatrixBufferVP8 {
    /// Creates the wrapper
    pub fn new(quantization_index: [[u16; 6usize]; 4usize]) -> Self {
        Self(Box::new(bindings::VAIQMatrixBufferVP8 {
            quantization_index,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAIQMatrixBufferVP8 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAIQMatrixBufferVP8 {
        self.0.as_ref()
    }
}

/// Wrapper over the VAIQMatrixBufferH264 FFI type
pub struct IQMatrixBufferH264(Box<bindings::VAIQMatrixBufferH264>);

impl IQMatrixBufferH264 {
    /// Creates the wrapper
    pub fn new(
        scaling_list4x4: [[u8; 16usize]; 6usize],
        scaling_list8x8: [[u8; 64usize]; 2usize],
    ) -> Self {
        Self(Box::new(bindings::VAIQMatrixBufferH264 {
            ScalingList4x4: scaling_list4x4,
            ScalingList8x8: scaling_list8x8,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAIQMatrixBufferH264 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAIQMatrixBufferH264 {
        self.0.as_ref()
    }
}

/// An abstraction over the IQMatrixBuffer types we support
pub enum IQMatrix {
    /// An abstraction over VAIQMatrixBufferMPEG2
    MPEG2(IQMatrixBufferMPEG2),
    /// An abstraction over VAIQMatrixBufferVP8
    VP8(IQMatrixBufferVP8),
    /// An abstraction over VAIQMatrixBufferH264
    H264(IQMatrixBufferH264),
}

/// Wrapper over the VAProbabilityDataBufferVP8 FFI type
pub struct ProbabilityDataBufferVP8(Box<bindings::VAProbabilityDataBufferVP8>);

impl ProbabilityDataBufferVP8 {
    /// Creates the wrapper
    pub fn new(dct_coeff_probs: [[[[u8; 11usize]; 3usize]; 8usize]; 4usize]) -> Self {
        Self(Box::new(bindings::VAProbabilityDataBufferVP8 {
            dct_coeff_probs,
            va_reserved: Default::default(),
        }))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut bindings::VAProbabilityDataBufferVP8 {
        self.0.as_mut()
    }

    /// Returns the inner FFI type. Useful for testing purposes.
    pub fn inner(&self) -> &bindings::VAProbabilityDataBufferVP8 {
        self.0.as_ref()
    }
}

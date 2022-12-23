// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Can't reasonably expect client code to consume everything that has been parsed.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Cursor;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use bytes::Buf;
use enumn::N;

use crate::decoders::h264::nalu_reader::NaluReader;

const DEFAULT_4X4_INTRA: [u8; 16] = [
    6, 13, 13, 20, 20, 20, 28, 28, 28, 28, 32, 32, 32, 37, 37, 42,
];

const DEFAULT_4X4_INTER: [u8; 16] = [
    10, 14, 14, 20, 20, 20, 24, 24, 24, 24, 27, 27, 27, 30, 30, 34,
];

const DEFAULT_8X8_INTRA: [u8; 64] = [
    6, 10, 10, 13, 11, 13, 16, 16, 16, 16, 18, 18, 18, 18, 18, 23, 23, 23, 23, 23, 23, 25, 25, 25,
    25, 25, 25, 25, 27, 27, 27, 27, 27, 27, 27, 27, 29, 29, 29, 29, 29, 29, 29, 31, 31, 31, 31, 31,
    31, 33, 33, 33, 33, 33, 36, 36, 36, 36, 38, 38, 38, 40, 40, 42,
];

const DEFAULT_8X8_INTER: [u8; 64] = [
    9, 13, 13, 15, 13, 15, 17, 17, 17, 17, 19, 19, 19, 19, 19, 21, 21, 21, 21, 21, 21, 22, 22, 22,
    22, 22, 22, 22, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 27, 27, 27, 27, 27,
    27, 28, 28, 28, 28, 28, 30, 30, 30, 30, 32, 32, 32, 33, 33, 35,
];

const MAX_PPS_COUNT: usize = 256;
const MAX_SPS_COUNT: usize = 32;
///
/// The maximum number of pictures in the DPB, as per A.3.1, clause h)
const DPB_MAX_SIZE: usize = 16;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Point<T> {
    pub x: T,
    pub y: T,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Rect<T> {
    pub min: Point<T>,
    pub max: Point<T>,
}

#[derive(N, Debug)]
pub enum NaluType {
    Unknown = 0,
    Slice = 1,
    SliceDpa = 2,
    SliceDpb = 3,
    SliceDpc = 4,
    SliceIdr = 5,
    Sei = 6,
    Sps = 7,
    Pps = 8,
    AuDelimiter = 9,
    SeqEnd = 10,
    StreamEnd = 11,
    FillerData = 12,
    SpsExt = 13,
    PrefixUnit = 14,
    SubsetSps = 15,
    DepthSps = 16,
    SliceAux = 19,
    SliceExt = 20,
    SliceDepth = 21,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefPicListModification {
    modification_of_pic_nums_idc: u8,
    /* if modification_of_pic_nums_idc == 0 || 1 */
    abs_diff_pic_num_minus1: u32,
    /* if modification_of_pic_nums_idc == 2 */
    long_term_pic_num: u32,
    /* if modification_of_pic_nums_idc == 4 || 5 */
    abs_diff_view_idx_minus1: u32,
}

impl RefPicListModification {
    pub fn modification_of_pic_nums_idc(&self) -> u8 {
        self.modification_of_pic_nums_idc
    }
    pub fn abs_diff_pic_num_minus1(&self) -> u32 {
        self.abs_diff_pic_num_minus1
    }
    pub fn long_term_pic_num(&self) -> u32 {
        self.long_term_pic_num
    }
    pub fn abs_diff_view_idx_minus1(&self) -> u32 {
        self.abs_diff_view_idx_minus1
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PredWeightTable {
    luma_log2_weight_denom: u8,
    chroma_log2_weight_denom: u8,

    luma_weight_l0: [i16; 32],
    luma_offset_l0: [i8; 32],

    /* if seq->ChromaArrayType != 0 */
    chroma_weight_l0: [[i16; 2]; 32],
    chroma_offset_l0: [[i8; 2]; 32],

    /* if slice->slice_type % 5 == 1 */
    luma_weight_l1: [i16; 32],
    luma_offset_l1: [i16; 32],

    /* and if seq->ChromaArrayType != 0 */
    chroma_weight_l1: [[i16; 2]; 32],
    chroma_offset_l1: [[i8; 2]; 32],
}

impl PredWeightTable {
    pub fn luma_log2_weight_denom(&self) -> u8 {
        self.luma_log2_weight_denom
    }
    pub fn chroma_log2_weight_denom(&self) -> u8 {
        self.chroma_log2_weight_denom
    }
    pub fn luma_weight_l0(&self) -> [i16; 32] {
        self.luma_weight_l0
    }
    pub fn luma_offset_l0(&self) -> [i8; 32] {
        self.luma_offset_l0
    }
    pub fn chroma_weight_l0(&self) -> [[i16; 2]; 32] {
        self.chroma_weight_l0
    }
    pub fn chroma_offset_l0(&self) -> [[i8; 2]; 32] {
        self.chroma_offset_l0
    }
    pub fn luma_weight_l1(&self) -> [i16; 32] {
        self.luma_weight_l1
    }
    pub fn luma_offset_l1(&self) -> [i16; 32] {
        self.luma_offset_l1
    }
    pub fn chroma_weight_l1(&self) -> [[i16; 2]; 32] {
        self.chroma_weight_l1
    }
    pub fn chroma_offset_l1(&self) -> [[i8; 2]; 32] {
        self.chroma_offset_l1
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefPicMarkingInner {
    /// Specifies a control operation to be applied to affect the reference
    /// picture marking. The `memory_management_control_operation` syntax element
    /// is followed by data necessary for the operation specified by the value
    /// of `memory_management_control_operation`. The values and control
    /// operations associated with `memory_management_control_operation` are
    /// specified in Table 7-9
    memory_management_control_operation: u8,

    /// Used (with memory_management_control_operation equal to 3 or 1) to
    /// assign a long-term frame index to a short-term reference picture or to
    /// mark a short-term reference picture as "unused for reference".
    difference_of_pic_nums_minus1: u32,

    /// Used (with memory_management_control_operation equal to 2) to mark a
    /// long-term reference picture as "unused for reference".
    long_term_pic_num: u32,

    /// Used (with memory_management_control_operation equal to 3 or 6) to
    /// assign a long-term frame index to a picture.
    long_term_frame_idx: u32,

    /// Minus 1 specifies the maximum value of long-term frame index allowed for
    /// long-term reference pictures (until receipt of another value of
    /// `max_long_term_frame_idx_plus1`).
    max_long_term_frame_idx_plus1: i32,
}

impl RefPicMarkingInner {
    pub fn memory_management_control_operation(&self) -> u8 {
        self.memory_management_control_operation
    }
    pub fn difference_of_pic_nums_minus1(&self) -> u32 {
        self.difference_of_pic_nums_minus1
    }
    pub fn long_term_pic_num(&self) -> u32 {
        self.long_term_pic_num
    }
    pub fn long_term_frame_idx(&self) -> u32 {
        self.long_term_frame_idx
    }
    pub fn max_long_term_frame_idx_plus1(&self) -> i32 {
        self.max_long_term_frame_idx_plus1
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefPicMarking {
    /// Specifies how the previously-decoded pictures in the decoded picture
    /// buffer are treated after decoding of an IDR picture. See Annex C.
    no_output_of_prior_pics_flag: bool,

    /// If unset, specifies that the MaxLongTermFrameIdx variable is set equal
    /// to "no long-term frame indices" and that the IDR picture is marked as
    /// "used for short-term reference". If set, specifies that the
    /// MaxLongTermFrameIdx variable is set equal to 0 and that the current IDR
    /// picture is marked "used for long-term reference" and is assigned
    /// LongTermFrameIdx equal to 0.
    long_term_reference_flag: bool,

    /// Selects the reference picture marking mode of the currently decoded
    /// picture as specified in Table 7-8.
    adaptive_ref_pic_marking_mode_flag: bool,

    /// An Vec with additional data used in the marking process.
    inner: Vec<RefPicMarkingInner>,
}

impl RefPicMarking {
    pub fn no_output_of_prior_pics_flag(&self) -> bool {
        self.no_output_of_prior_pics_flag
    }
    pub fn long_term_reference_flag(&self) -> bool {
        self.long_term_reference_flag
    }
    pub fn adaptive_ref_pic_marking_mode_flag(&self) -> bool {
        self.adaptive_ref_pic_marking_mode_flag
    }
    pub fn inner(&self) -> &Vec<RefPicMarkingInner> {
        &self.inner
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SliceHeader {
    /// Specifies the address of the first macroblock in the slice.
    first_mb_in_slice: u32,

    /// Specifies the coding type of the slice according to Table 7-6.
    slice_type: SliceType,

    // Specifies the picture parameter set in use
    pic_parameter_set_id: u8,

    /// Specifies the colour plane associated with the current slice RBSP when
    /// `separate_colour_plane_flag` is set.
    colour_plane_id: u8,

    /// Used as an identifier for pictures and shall be represented by
    /// `log2_max_frame_num_minus4 + 4` bits in the bitstream.
    frame_num: u16,

    /// If set, specifies that the slice is a slice of a coded field. If not
    /// set, specifies that the slice is a slice of a coded frame.
    field_pic_flag: bool,

    /// If set, specifies that the slice is part of a coded bottom field. If not
    /// set, specifies that the picture is a coded top field.
    bottom_field_flag: bool,

    /// Identifies an IDR picture. The values of `idr_pic_id` in all the slices
    /// of an IDR picture shall remain unchanged. When two consecutive access
    /// units in decoding order are both IDR access units, the value of
    /// `idr_pic_id` in the slices of the first such IDR access unit shall
    /// differ from the `idr_pic_id` in the second such IDR access unit
    idr_pic_id: u16,

    /// Specifies the picture order count modulo `MaxPicOrderCntLsb` for the top
    /// field of a coded frame or for a coded field. The length of the
    /// `pic_order_cnt_lsb` syntax element is
    /// `log2_max_pic_order_cnt_lsb_minus4` + 4 bits.
    pic_order_cnt_lsb: u16,

    ///  Specifies the picture order count difference between the bottom field
    ///  and the top field of a coded frame as follows
    delta_pic_order_cnt_bottom: i32,

    /// The first entry specifies the picture order count difference from the
    /// expected picture order count for the top field of a coded frame or for a
    /// coded field as specified in clause 8.2.1 The second entry  specifies the
    /// picture order count difference from the expected picture order count for
    /// the bottom field of a coded frame specified in clause 8.2.1.
    delta_pic_order_cnt: [i32; 2],

    /// Shall be equal to 0 for slices and slice data partitions belonging to
    /// the primary coded picture. The value of `redundant_pic_cnt shall` be
    /// greater than 0 for coded slices or coded slice data partitions of a
    /// redundant coded picture
    redundant_pic_cnt: u8,

    /// Specifies the method used in the decoding process to derive motion
    /// vectors and reference indices for inter prediction >
    direct_spatial_mv_pred_flag: bool,

    /// If set, specifies that the syntax element `num_ref_idx_l0_active_minus1`
    /// is present for P, SP, and B slices and that the syntax element
    /// `num_ref_idx_l1_active_minus1` is present for B slices. If not set,
    /// specifies that the syntax elements `num_ref_idx_l0_active_minus1` and
    /// `num_ref_idx_l1_active_minus1` are not present.
    num_ref_idx_active_override_flag: bool,

    /// Specifies the maximum reference index for reference picture list 0 that
    /// shall be used to decode the slice.
    num_ref_idx_l0_active_minus1: u8,

    /// Specifies the maximum reference index for reference picture list 1 that
    /// shall be used to decode the slice.
    num_ref_idx_l1_active_minus1: u8,

    /// If set, specifies that the syntax element `modification_of_pic_nums_idc`
    /// is present for specifying reference picture list 0. If not set,
    /// specifies that this syntax element is not present.
    ref_pic_list_modification_flag_l0: bool,

    /// Reference picture list 0 modification as parsed with the
    /// `ref_pic_list_modification()` process.
    ref_pic_list_modification_l0: Vec<RefPicListModification>,

    /// If set, specifies that the syntax element `modification_of_pic_nums_idc`
    /// is present for specifying reference picture list 1. If not set,
    /// specifies that this syntax element is not present.
    ref_pic_list_modification_flag_l1: bool,

    /// Reference picture list 1 modification as parsed with the
    /// `ref_pic_list_modification()` process.
    ref_pic_list_modification_l1: Vec<RefPicListModification>,

    /// Prediction weight table as parsed using 7.3.3.2
    pred_weight_table: PredWeightTable,

    /// Decoded reference picture marking parsed using 7.3.3.3
    dec_ref_pic_marking: RefPicMarking,

    /// Specifies the index for determining the initialization table used in the
    /// initialization process for context variables.
    cabac_init_idc: u8,

    /// Specifies the initial value of QP Y to be used for all the macroblocks
    /// in the slice until modified by the value of `mb_qp_delta` in the
    /// macroblock layer. The initial QPY quantization parameter for the slice
    /// is computed using 7-30.
    slice_qp_delta: i8,

    /// Specifies the decoding process to be used to decode P macroblocks in an
    /// SP slice.
    sp_for_switch_flag: bool,

    /// Specifies the value of QSY for all the macroblocks in SP and SI slices.
    /// The QSY quantization parameter for the slice is computed using 7-31.
    slice_qs_delta: i8,

    /// Specifies whether the operation of the deblocking filter shall be
    /// disabled across some block edges of the slice and specifies for which
    /// edges the filtering is disabled.
    disable_deblocking_filter_idc: u8,

    /// Specifies the offset used in accessing the α and tC0 deblocking filter
    /// tables for filtering operations controlled by the macroblocks within the
    /// slice. From this value, the offset that shall be applied when addressing
    /// these tables shall be computed using 7-32.
    slice_alpha_c0_offset_div2: i8,

    /// Specifies the offset used in accessing the β deblocking filter table for
    /// filtering operations controlled by the macroblocks within the slice.
    /// From this value, the offset that is applied when addressing the β table
    /// of the deblocking filter shall be computed using 7-33.
    slice_beta_offset_div2: i8,

    /// Same as `MaxPicNum` in the specification.
    max_pic_num: u32,

    /// Size of the slice_header() in bits
    header_bit_size: usize,

    /// Number of emulation prevention bytes (EPB) in this slice_header()
    n_emulation_prevention_bytes: usize,
}

impl SliceHeader {
    pub fn first_mb_in_slice(&self) -> u32 {
        self.first_mb_in_slice
    }
    pub fn slice_type(&self) -> &SliceType {
        &self.slice_type
    }
    pub fn pic_parameter_set_id(&self) -> u8 {
        self.pic_parameter_set_id
    }
    pub fn colour_plane_id(&self) -> u8 {
        self.colour_plane_id
    }
    pub fn frame_num(&self) -> u16 {
        self.frame_num
    }
    pub fn field_pic_flag(&self) -> bool {
        self.field_pic_flag
    }
    pub fn bottom_field_flag(&self) -> bool {
        self.bottom_field_flag
    }
    pub fn idr_pic_id(&self) -> u16 {
        self.idr_pic_id
    }
    pub fn pic_order_cnt_lsb(&self) -> u16 {
        self.pic_order_cnt_lsb
    }
    pub fn delta_pic_order_cnt_bottom(&self) -> i32 {
        self.delta_pic_order_cnt_bottom
    }
    pub fn delta_pic_order_cnt(&self) -> [i32; 2] {
        self.delta_pic_order_cnt
    }
    pub fn redundant_pic_cnt(&self) -> u8 {
        self.redundant_pic_cnt
    }
    pub fn direct_spatial_mv_pred_flag(&self) -> bool {
        self.direct_spatial_mv_pred_flag
    }
    pub fn num_ref_idx_active_override_flag(&self) -> bool {
        self.num_ref_idx_active_override_flag
    }
    pub fn num_ref_idx_l0_active_minus1(&self) -> u8 {
        self.num_ref_idx_l0_active_minus1
    }
    pub fn num_ref_idx_l1_active_minus1(&self) -> u8 {
        self.num_ref_idx_l1_active_minus1
    }
    pub fn ref_pic_list_modification_flag_l0(&self) -> bool {
        self.ref_pic_list_modification_flag_l0
    }
    pub fn ref_pic_list_modification_l0(&self) -> &Vec<RefPicListModification> {
        &self.ref_pic_list_modification_l0
    }
    pub fn ref_pic_list_modification_flag_l1(&self) -> bool {
        self.ref_pic_list_modification_flag_l1
    }
    pub fn ref_pic_list_modification_l1(&self) -> &Vec<RefPicListModification> {
        &self.ref_pic_list_modification_l1
    }
    pub fn pred_weight_table(&self) -> &PredWeightTable {
        &self.pred_weight_table
    }
    pub fn dec_ref_pic_marking(&self) -> &RefPicMarking {
        &self.dec_ref_pic_marking
    }
    pub fn cabac_init_idc(&self) -> u8 {
        self.cabac_init_idc
    }
    pub fn slice_qp_delta(&self) -> i8 {
        self.slice_qp_delta
    }
    pub fn sp_for_switch_flag(&self) -> bool {
        self.sp_for_switch_flag
    }
    pub fn slice_qs_delta(&self) -> i8 {
        self.slice_qs_delta
    }
    pub fn disable_deblocking_filter_idc(&self) -> u8 {
        self.disable_deblocking_filter_idc
    }
    pub fn slice_alpha_c0_offset_div2(&self) -> i8 {
        self.slice_alpha_c0_offset_div2
    }
    pub fn slice_beta_offset_div2(&self) -> i8 {
        self.slice_beta_offset_div2
    }
    pub fn max_pic_num(&self) -> u32 {
        self.max_pic_num
    }
    pub fn header_bit_size(&self) -> usize {
        self.header_bit_size
    }
    pub fn n_emulation_prevention_bytes(&self) -> usize {
        self.n_emulation_prevention_bytes
    }
}

/// A H264 slice. An integer number of macroblocks or macroblock pairs ordered
/// consecutively in the raster scan within a particular slice group
pub struct Slice<T> {
    /// The slice header.
    header: SliceHeader,
    /// The NAL unit backing this slice.
    nalu: Nalu<T>,
}

impl<T> Slice<T> {
    /// Get a reference to the slice's header.
    pub fn header(&self) -> &SliceHeader {
        &self.header
    }

    /// Get a reference to the slice's nalu.
    pub fn nalu(&self) -> &Nalu<T> {
        &self.nalu
    }
}

#[derive(N, Clone, Copy, Debug, PartialEq, Eq)]
/// See table 7-6 in the specification.
pub enum SliceType {
    P = 0,
    B = 1,
    I = 2,
    Sp = 3,
    Si = 4,
}

impl SliceType {
    /// Whether this is a P slice. See table 7-6 in the specification.
    pub fn is_p(&self) -> bool {
        matches!(self, SliceType::P)
    }

    /// Whether this is a B slice. See table 7-6 in the specification.
    pub fn is_b(&self) -> bool {
        matches!(self, SliceType::B)
    }

    /// Whether this is an I slice. See table 7-6 in the specification.
    pub fn is_i(&self) -> bool {
        matches!(self, SliceType::I)
    }

    /// Whether this is a SP slice. See table 7-6 in the specification.
    pub fn is_sp(&self) -> bool {
        matches!(self, SliceType::Sp)
    }

    /// Whether this is a SI slice. See table 7-6 in the specification.
    pub fn is_si(&self) -> bool {
        matches!(self, SliceType::Si)
    }
}

impl Default for SliceType {
    fn default() -> Self {
        Self::P
    }
}

#[derive(N)]
pub enum Profile {
    Baseline = 66,
    Main = 77,
    High = 100,
}

#[derive(N, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    L1 = 10,
    L1B = 9,
    L1_1 = 11,
    L1_2 = 12,
    L1_3 = 13,
    L2_0 = 20,
    L2_1 = 21,
    L2_2 = 22,
    L3 = 30,
    L3_1 = 31,
    L3_2 = 32,
    L4 = 40,
    L4_1 = 41,
    L4_2 = 42,
    L5 = 50,
    L5_1 = 51,
    L5_2 = 52,
    L6 = 60,
    L6_1 = 61,
    L6_2 = 62,
}

impl Default for Level {
    fn default() -> Self {
        Level::L1
    }
}

/// A H264 Sequence Parameter Set. A syntax structure containing syntax elements
/// that apply to zero or more entire coded video sequences as determined by the
/// content of a seq_parameter_set_id syntax element found in the picture
/// parameter set referred to by the pic_parameter_set_id syntax element found
/// in each slice header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sps {
    /// Identifies the sequence parameter set that is referred to by the picture
    /// parameter set
    seq_parameter_set_id: u8,

    /// Profile to which the coded video sequence conforms
    profile_idc: u8,

    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set0_flag: bool,
    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set1_flag: bool,
    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set2_flag: bool,
    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set3_flag: bool,
    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set4_flag: bool,
    /// Retains the same meaning as in the specification. See 7.4.2.1.1
    constraint_set5_flag: bool,

    /// Level to which the coded video sequence conforms
    level_idc: Level,

    /// Specifies the chroma sampling relative to the luma sampling as specified
    /// in clause 6.2.
    chroma_format_idc: u8,

    /// Specifies whether the three colour components of the 4:4:4 chroma format
    /// are coded separately.
    separate_colour_plane_flag: bool,

    /// Specifies the bit depth of the samples of the luma array and the value
    /// of the luma quantization parameter range offset QpBdOffsetY. See 7-3 and
    /// 7-4.
    bit_depth_luma_minus8: u8,

    /// Specifies the bit depth of the samples of the chroma arrays and the
    /// value of the chroma quantization parameter range offset QpBdOffsetC. See
    /// 7-5 and 7-6.
    bit_depth_chroma_minus8: u8,

    /// qpprime_y_zero_transform_bypass_flag equal to 1 specifies that, when
    /// QP′Y is equal to 0, a transform bypass operation for the transform
    /// coefficient decoding process and picture construction process prior to
    /// deblocking filter process as specified in clause 8.5 shall be applied.
    /// qpprime_y_zero_transform_bypass_flag equal to 0 specifies that the
    /// transform coefficient decoding process and picture construction process
    /// prior to deblocking filter process shall not use the transform bypass
    /// operation
    /// QP′Y is defined in 7-38 as QP′Y = QPY + QpBdOffsetY
    qpprime_y_zero_transform_bypass_flag: bool,

    /// Whether `seq_scaling_list_present_flag[i]` for i = 0..7 or i = 0..11 is
    /// present or whether the sequence level scaling list shall be specified by
    /// Flat_4x4_16 for i = 0..5 and flat_8x8_16 for i = 6..11
    seq_scaling_matrix_present_flag: bool,

    /// 4x4 Scaling list as read with 7.3.2.1.1.1
    scaling_lists_4x4: [[u8; 16]; 6],
    /// 8x8 Scaling list as read with 7.3.2.1.1.1
    scaling_lists_8x8: [[u8; 64]; 6],

    /// Specifies the value of the variable MaxFrameNum that is used in
    /// frame_num related derivations as follows: MaxFrameNum = 2 ^
    /// (log2_max_frame_num_minus4 + 4 )
    log2_max_frame_num_minus4: u8,

    /// Specifies the method to decode picture order count (as specified in
    /// clause 8.2.1)
    pic_order_cnt_type: u8,

    /// Specifies the value of the variable MaxPicOrderCntLsb that is used in
    /// the decoding process for picture order count as specified in clause
    /// 8.2.1 as follows: MaxPicOrderCntLsb = 2 ^ (
    /// log2_max_pic_order_cnt_lsb_minus4 + 4 ).
    log2_max_pic_order_cnt_lsb_minus4: u8,

    /// If true, specifies that `delta_pic_order_cnt[0]` and
    /// `delta_pic_order_cnt[1]` are not present in the slice headers of the
    /// sequence and shall be inferred to be equal to 0.
    /// If false, specifies that `delta_pic_order_cnt[0]` is present in the
    /// slice headers of the sequence and `delta_pic_order_cnt[1]` may be
    /// present in the slice headers of the sequence.
    delta_pic_order_always_zero_flag: bool,

    /// Used to calculate the picture order count of a non-reference picture as
    /// specified in clause 8.2.1.
    offset_for_non_ref_pic: i32,

    /// Used to calculate the picture order count of a bottom field as specified
    /// in clause 8.2.1.
    offset_for_top_to_bottom_field: i32,

    /// Used in the decoding process for picture order count as specified in
    /// clause 8.2.1
    num_ref_frames_in_pic_order_cnt_cycle: u8,

    /// An element of a list of num_ref_frames_in_pic_order_cnt_cycle values
    /// used in the decoding process for picture order count as specified in
    /// clause 8.2.
    offset_for_ref_frame: [i32; 255],

    /// Specifies the maximum number of short-term and long-term reference
    /// frames, complementary reference field pairs, and non-paired reference
    /// fields that may be used by the decoding process for inter prediction of
    /// any picture in the coded video sequence. Also
    /// determines the size of the sliding window operation as specified in
    /// clause 8.2.5.3.
    max_num_ref_frames: u32,

    /// Specifies the allowed values of frame_num as specified in clause 7.4.3
    /// and the decoding process in case of an inferred gap between values of
    /// frame_num as specified in clause 8.2.5.2
    gaps_in_frame_num_value_allowed_flag: bool,

    /// Plus 1 specifies the width of each decoded picture in units of
    /// macroblocks.
    pic_width_in_mbs_minus1: u32,
    /// Plus 1 specifies the height in slice group map units of a decoded frame
    /// or field.
    pic_height_in_map_units_minus1: u32,

    /// If true,  specifies that every coded picture of the coded video sequence
    /// is a coded frame containing only frame macroblocks, else specifies that
    /// coded pictures of the coded video sequence may either be coded fields or
    /// coded frames.
    frame_mbs_only_flag: bool,

    /// If true, specifies the possible use of switching between frame and field
    /// macroblocks within frames, else, specifies no switching between frame
    /// and field macroblocks within a picture.
    mb_adaptive_frame_field_flag: bool,

    /// Specifies the method used in the derivation process for luma motion
    /// vectors for B_Skip, B_Direct_16x16 and B_Direct_8x8 as specified in
    /// clause 8.4.1.2.
    direct_8x8_inference_flag: bool,

    /// If true, specifies that the frame cropping offset parameters follow next
    /// in the sequence parameter, else specifies that the frame cropping offset
    /// parameters are not present
    frame_cropping_flag: bool,

    /// Specify the samples of the pictures in the coded video sequence that are
    /// output from the decoding process, in terms of a rectangular region
    /// specified in frame coordinates for output.
    frame_crop_left_offset: u32,
    /// Specify the samples of the pictures in the coded video sequence that are
    /// output from the decoding process, in terms of a rectangular region
    /// specified in frame coordinates for output.
    frame_crop_right_offset: u32,
    /// Specify the samples of the pictures in the coded video sequence that are
    /// output from the decoding process, in terms of a rectangular region
    /// specified in frame coordinates for output.
    frame_crop_top_offset: u32,
    /// Specify the samples of the pictures in the coded video sequence that are
    /// output from the decoding process, in terms of a rectangular region
    /// specified in frame coordinates for output.
    frame_crop_bottom_offset: u32,

    // Calculated
    /// Same as ChromaArrayType. See the definition in the specification.
    chroma_array_type: u8,
    /// Same as MaxFrameNum. See 7-10 in the specification.
    max_frame_num: u32,
    /// See 7-13 through 7-17 in the specification.
    width: u32,
    /// See 7-13 through 7-17 in the specification.
    height: u32,
    /// See the documentation for frame_crop_{left|right|top|bottom}_offset in
    /// the specification
    crop_rect_width: u32,
    /// See the documentation for frame_crop_{left|right|top|bottom}_offset in
    /// the specification
    crop_rect_height: u32,
    /// See the documentation for frame_crop_{left|right|top|bottom}_offset in
    /// the specification
    crop_rect_x: u32,
    /// See the documentation for frame_crop_{left|right|top|bottom}_offset in
    /// the specification
    crop_rect_y: u32,
    /// Same as ExpectedDeltaPerPicOrderCntCycle, see 7-12 in the specification.
    expected_delta_per_pic_order_cnt_cycle: i32,

    vui_parameters_present_flag: bool,
    vui_parameters: VuiParams,
}

impl Sps {
    pub fn seq_parameter_set_id(&self) -> u8 {
        self.seq_parameter_set_id
    }
    pub fn profile_idc(&self) -> u8 {
        self.profile_idc
    }
    pub fn constraint_set0_flag(&self) -> bool {
        self.constraint_set0_flag
    }
    pub fn constraint_set1_flag(&self) -> bool {
        self.constraint_set1_flag
    }
    pub fn constraint_set2_flag(&self) -> bool {
        self.constraint_set2_flag
    }
    pub fn constraint_set3_flag(&self) -> bool {
        self.constraint_set3_flag
    }
    pub fn constraint_set4_flag(&self) -> bool {
        self.constraint_set4_flag
    }
    pub fn constraint_set5_flag(&self) -> bool {
        self.constraint_set5_flag
    }
    pub fn level_idc(&self) -> Level {
        self.level_idc
    }
    pub fn chroma_format_idc(&self) -> u8 {
        self.chroma_format_idc
    }
    pub fn separate_colour_plane_flag(&self) -> bool {
        self.separate_colour_plane_flag
    }
    pub fn bit_depth_luma_minus8(&self) -> u8 {
        self.bit_depth_luma_minus8
    }
    pub fn bit_depth_chroma_minus8(&self) -> u8 {
        self.bit_depth_chroma_minus8
    }
    pub fn qpprime_y_zero_transform_bypass_flag(&self) -> bool {
        self.qpprime_y_zero_transform_bypass_flag
    }
    pub fn seq_scaling_matrix_present_flag(&self) -> bool {
        self.seq_scaling_matrix_present_flag
    }
    pub fn scaling_lists_4x4(&self) -> [[u8; 16]; 6] {
        self.scaling_lists_4x4
    }
    pub fn scaling_lists_8x8(&self) -> [[u8; 64]; 6] {
        self.scaling_lists_8x8
    }
    pub fn log2_max_frame_num_minus4(&self) -> u8 {
        self.log2_max_frame_num_minus4
    }
    pub fn pic_order_cnt_type(&self) -> u8 {
        self.pic_order_cnt_type
    }
    pub fn log2_max_pic_order_cnt_lsb_minus4(&self) -> u8 {
        self.log2_max_pic_order_cnt_lsb_minus4
    }
    pub fn delta_pic_order_always_zero_flag(&self) -> bool {
        self.delta_pic_order_always_zero_flag
    }
    pub fn offset_for_non_ref_pic(&self) -> i32 {
        self.offset_for_non_ref_pic
    }
    pub fn offset_for_top_to_bottom_field(&self) -> i32 {
        self.offset_for_top_to_bottom_field
    }
    pub fn num_ref_frames_in_pic_order_cnt_cycle(&self) -> u8 {
        self.num_ref_frames_in_pic_order_cnt_cycle
    }
    pub fn offset_for_ref_frame(&self) -> [i32; 255] {
        self.offset_for_ref_frame
    }
    pub fn max_num_ref_frames(&self) -> u32 {
        self.max_num_ref_frames
    }
    pub fn gaps_in_frame_num_value_allowed_flag(&self) -> bool {
        self.gaps_in_frame_num_value_allowed_flag
    }
    pub fn pic_width_in_mbs_minus1(&self) -> u32 {
        self.pic_width_in_mbs_minus1
    }
    pub fn pic_height_in_map_units_minus1(&self) -> u32 {
        self.pic_height_in_map_units_minus1
    }
    pub fn frame_mbs_only_flag(&self) -> bool {
        self.frame_mbs_only_flag
    }
    pub fn mb_adaptive_frame_field_flag(&self) -> bool {
        self.mb_adaptive_frame_field_flag
    }
    pub fn direct_8x8_inference_flag(&self) -> bool {
        self.direct_8x8_inference_flag
    }
    pub fn frame_cropping_flag(&self) -> bool {
        self.frame_cropping_flag
    }
    pub fn frame_crop_left_offset(&self) -> u32 {
        self.frame_crop_left_offset
    }
    pub fn frame_crop_right_offset(&self) -> u32 {
        self.frame_crop_right_offset
    }
    pub fn frame_crop_top_offset(&self) -> u32 {
        self.frame_crop_top_offset
    }
    pub fn frame_crop_bottom_offset(&self) -> u32 {
        self.frame_crop_bottom_offset
    }
    pub fn chroma_array_type(&self) -> u8 {
        self.chroma_array_type
    }
    pub fn max_frame_num(&self) -> u32 {
        self.max_frame_num
    }
    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn crop_rect_width(&self) -> u32 {
        self.crop_rect_width
    }
    pub fn crop_rect_height(&self) -> u32 {
        self.crop_rect_height
    }
    pub fn crop_rect_x(&self) -> u32 {
        self.crop_rect_x
    }
    pub fn crop_rect_y(&self) -> u32 {
        self.crop_rect_y
    }
    pub fn expected_delta_per_pic_order_cnt_cycle(&self) -> i32 {
        self.expected_delta_per_pic_order_cnt_cycle
    }
    pub fn vui_parameters_present_flag(&self) -> bool {
        self.vui_parameters_present_flag
    }
    pub fn vui_parameters(&self) -> &VuiParams {
        &self.vui_parameters
    }

    pub fn visible_rectangle(&self) -> Rect<u32> {
        if !self.frame_cropping_flag {
            return Rect {
                min: Point { x: 0, y: 0 },
                max: Point {
                    x: self.width,
                    y: self.height,
                },
            };
        }

        let crop_unit_x;
        let crop_unit_y;
        if self.chroma_array_type == 0 {
            crop_unit_x = 1;
            crop_unit_y = if self.frame_mbs_only_flag { 1 } else { 2 };
        } else {
            let sub_width_c = if self.chroma_format_idc > 2 { 1 } else { 2 };
            let sub_height_c = if self.chroma_format_idc > 1 { 1 } else { 2 };
            crop_unit_x = sub_width_c;
            crop_unit_y = sub_height_c * (if self.frame_mbs_only_flag { 1 } else { 2 });
        }

        let crop_left = crop_unit_x * self.frame_crop_left_offset;
        let crop_right = crop_unit_x * self.frame_crop_right_offset;
        let crop_top = crop_unit_y * self.frame_crop_top_offset;
        let crop_bottom = crop_unit_y * self.frame_crop_bottom_offset;

        Rect {
            min: Point {
                x: crop_left,
                y: crop_top,
            },
            max: Point {
                x: self.width - crop_left - crop_right,
                y: self.height - crop_top - crop_bottom,
            },
        }
    }

    pub fn max_dpb_frames(&self) -> Result<usize> {
        let profile = Profile::n(self.profile_idc())
            .with_context(|| format!("Unsupported profile {}", self.profile_idc()))?;
        let mut level = self.level_idc();

        // A.3.1 and A.3.2: Level 1b for Baseline, Constrained Baseline and Main
        // profile if level_idc == 11 and constraint_set3_flag == 1
        if matches!(level, Level::L1_1)
            && (matches!(profile, Profile::Baseline) || matches!(profile, Profile::Main))
            && self.constraint_set3_flag()
        {
            level = Level::L1B;
        };

        // Table A.1
        let max_dpb_mbs = match level {
            Level::L1 => 396,
            Level::L1B => 396,
            Level::L1_1 => 900,
            Level::L1_2 => 2376,
            Level::L1_3 => 2376,
            Level::L2_0 => 2376,
            Level::L2_1 => 4752,
            Level::L2_2 => 8100,
            Level::L3 => 8100,
            Level::L3_1 => 18000,
            Level::L3_2 => 20480,
            Level::L4 => 32768,
            Level::L4_1 => 32768,
            Level::L4_2 => 34816,
            Level::L5 => 110400,
            Level::L5_1 => 184320,
            Level::L5_2 => 184320,
            Level::L6 => 696320,
            Level::L6_1 => 696320,
            Level::L6_2 => 696320,
        };

        let width_mb = self.width() / 16;
        let height_mb = self.height() / 16;

        let max_dpb_frames =
            std::cmp::min(max_dpb_mbs / (width_mb * height_mb), DPB_MAX_SIZE as u32) as usize;

        let mut max_dpb_frames = std::cmp::max(max_dpb_frames, self.max_num_ref_frames() as usize);

        if self.vui_parameters_present_flag() && self.vui_parameters().bitstream_restriction_flag()
        {
            max_dpb_frames = std::cmp::max(
                1,
                self.vui_parameters()
                    .max_dec_frame_buffering()
                    .try_into()
                    .unwrap(),
            );
        }

        Ok(max_dpb_frames)
    }
}

impl Default for Sps {
    fn default() -> Self {
        Self {
            scaling_lists_4x4: [[0; 16]; 6],
            scaling_lists_8x8: [[0; 64]; 6],
            offset_for_ref_frame: [0; 255],
            seq_parameter_set_id: Default::default(),
            profile_idc: Default::default(),
            constraint_set0_flag: Default::default(),
            constraint_set1_flag: Default::default(),
            constraint_set2_flag: Default::default(),
            constraint_set3_flag: Default::default(),
            constraint_set4_flag: Default::default(),
            constraint_set5_flag: Default::default(),
            level_idc: Default::default(),
            chroma_format_idc: Default::default(),
            separate_colour_plane_flag: Default::default(),
            bit_depth_luma_minus8: Default::default(),
            bit_depth_chroma_minus8: Default::default(),
            qpprime_y_zero_transform_bypass_flag: Default::default(),
            seq_scaling_matrix_present_flag: Default::default(),
            log2_max_frame_num_minus4: Default::default(),
            pic_order_cnt_type: Default::default(),
            log2_max_pic_order_cnt_lsb_minus4: Default::default(),
            delta_pic_order_always_zero_flag: Default::default(),
            offset_for_non_ref_pic: Default::default(),
            offset_for_top_to_bottom_field: Default::default(),
            num_ref_frames_in_pic_order_cnt_cycle: Default::default(),
            max_num_ref_frames: Default::default(),
            gaps_in_frame_num_value_allowed_flag: Default::default(),
            pic_width_in_mbs_minus1: Default::default(),
            pic_height_in_map_units_minus1: Default::default(),
            frame_mbs_only_flag: Default::default(),
            mb_adaptive_frame_field_flag: Default::default(),
            direct_8x8_inference_flag: Default::default(),
            frame_cropping_flag: Default::default(),
            frame_crop_left_offset: Default::default(),
            frame_crop_right_offset: Default::default(),
            frame_crop_top_offset: Default::default(),
            frame_crop_bottom_offset: Default::default(),
            chroma_array_type: Default::default(),
            max_frame_num: Default::default(),
            width: Default::default(),
            height: Default::default(),
            crop_rect_width: Default::default(),
            crop_rect_height: Default::default(),
            crop_rect_x: Default::default(),
            crop_rect_y: Default::default(),
            expected_delta_per_pic_order_cnt_cycle: Default::default(),
            vui_parameters_present_flag: Default::default(),
            vui_parameters: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HrdParams {
    /// Plus 1 specifies the number of alternative CPB specifications in the
    /// bitstream. The value of `cpb_cnt_minus1` shall be in the range of 0 to 31,
    /// inclusive
    cpb_cnt_minus1: u8,
    /// Together with `bit_rate_value_minus1[ SchedSelIdx ]` specifies the
    /// maximum input bit rate of the `SchedSelIdx`-th CPB.
    bit_rate_scale: u8,
    /// Together with `cpb_size_value_minus1[ SchedSelIdx ]` specifies the CPB
    /// size of the SchedSelIdx-th CPB.
    cpb_size_scale: u8,

    /// `[ SchedSelIdx ]` (together with bit_rate_scale) specifies the maximum
    /// input bit rate for the SchedSelIdx-th CPB.
    bit_rate_value_minus1: [u32; 32],
    /// `[ SchedSelIdx ]` is used together with cpb_size_scale to specify the
    /// SchedSelIdx-th CPB size.
    cpb_size_value_minus1: [u32; 32],
    /// `[ SchedSelIdx ]` equal to 0 specifies that to decode this bitstream by
    /// the HRD using the `SchedSelIdx`-th CPB specification, the hypothetical
    /// stream delivery scheduler (HSS) operates in an intermittent bit rate
    /// mode. `cbr_flag[ SchedSelIdx ]` equal to 1 specifies that the HSS operates
    /// in a constant bit rate (CBR) mode
    cbr_flag: [bool; 32],

    /// Specifies the length in bits of the `initial_cpb_removal_delay[
    /// SchedSelIdx ]` and `initial_cpb_removal_delay_offset[ SchedSelIdx ]` syntax
    /// elements of the buffering period SEI message.
    initial_cpb_removal_delay_length_minus1: u8,
    /// Specifies the length in bits of the `cpb_removal_delay` syntax element.
    cpb_removal_delay_length_minus1: u8,
    /// Specifies the length in bits of the `dpb_output_delay` syntax element.
    dpb_output_delay_length_minus1: u8,
    /// If greater than 0, specifies the length in bits of the `time_offset`
    /// syntax element. `time_offset_length` equal to 0 specifies that the
    /// `time_offset` syntax element is not present
    time_offset_length: u8,
}

impl HrdParams {
    pub fn cpb_cnt_minus1(&self) -> u8 {
        self.cpb_cnt_minus1
    }
    pub fn bit_rate_scale(&self) -> u8 {
        self.bit_rate_scale
    }
    pub fn cpb_size_scale(&self) -> u8 {
        self.cpb_size_scale
    }
    pub fn bit_rate_value_minus1(&self) -> [u32; 32] {
        self.bit_rate_value_minus1
    }
    pub fn cpb_size_value_minus1(&self) -> [u32; 32] {
        self.cpb_size_value_minus1
    }
    pub fn cbr_flag(&self) -> [bool; 32] {
        self.cbr_flag
    }
    pub fn initial_cpb_removal_delay_length_minus1(&self) -> u8 {
        self.initial_cpb_removal_delay_length_minus1
    }
    pub fn cpb_removal_delay_length_minus1(&self) -> u8 {
        self.cpb_removal_delay_length_minus1
    }
    pub fn dpb_output_delay_length_minus1(&self) -> u8 {
        self.dpb_output_delay_length_minus1
    }
    pub fn time_offset_length(&self) -> u8 {
        self.time_offset_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VuiParams {
    /// Specifies whether `aspect_ratio_idc` is present.
    aspect_ratio_info_present_flag: bool,
    /// Specifies the value of the sample aspect ratio of the luma samples.
    /// Table E-1 shows the meaning of the code. When aspect_ratio_idc indicates
    /// Extended_SAR, the sample aspect ratio is represented by sar_width :
    /// sar_height. When the aspect_ratio_idc syntax element is not present,
    /// aspect_ratio_idc value shall be inferred to be equal to 0
    aspect_ratio_idc: u8,

    /* if aspect_ratio_idc == 255 */
    /// Indicates the horizontal size of the sample aspect ratio (in arbitrary
    /// units)
    sar_width: u16,
    /// Indicates the vertical size of the sample aspect ratio (in the same
    /// arbitrary units as sar_width).
    sar_height: u16,

    /// If true specifies that the overscan_appropriate_flag is present. Else,
    /// the preferred display method for the video signal is unspecified
    overscan_info_present_flag: bool,
    /* if overscan_info_present_flag */
    /// If true, indicates that the cropped decoded pictures output are suitable
    /// for display using overscan. Else, indicates that the cropped decoded
    /// pictures output contain visually important information in the entire
    /// region out to the edges of the cropping rectangle of the picture, such
    /// that the cropped decoded pictures output should not be displayed using
    /// overscan.
    overscan_appropriate_flag: bool,

    /// Specifies that video_format, video_full_range_flag and
    /// colour_description_present_flag are present
    video_signal_type_present_flag: bool,
    /// Indicates the representation of the pictures as specified in Table E-2,
    /// before being coded in accordance with this Recommendation |
    /// International Standard. When the video_format syntax element is not
    /// present, video_format value shall be inferred to be equal to 5.
    video_format: u8,
    /// Indicates the black level and range of the luma and chroma signals as
    /// derived from E′Y, E′PB, and E′PR or E′ R, E′G, and E′B real-valued
    /// component signals.
    video_full_range_flag: bool,
    /// Specifies that colour_primaries, transfer_characteristics and
    /// matrix_coefficients are present.
    colour_description_present_flag: bool,
    /// Indicates the chromaticity coordinates of the source primaries as
    /// specified in Table E-3 in terms of the CIE 1931 definition of x and y as
    /// specified by ISO 11664-1.
    colour_primaries: u8,
    /// Retains same meaning as in the specification.
    transfer_characteristics: u8,
    /// Describes the matrix coefficients used in deriving luma and chroma
    /// signals from the green, blue, and red, or Y, Z, and X primaries, as
    /// specified in Table E-5.
    matrix_coefficients: u8,

    /// Specifies that chroma_sample_loc_type_top_field and
    /// chroma_sample_loc_type_bottom_field are present
    chroma_loc_info_present_flag: bool,
    /// Specify the location of chroma samples. See the spec for more details.
    chroma_sample_loc_type_top_field: u8,
    /// Specify the location of chroma samples. See the spec for more details.
    chroma_sample_loc_type_bottom_field: u8,

    /// Specifies that num_units_in_tick, time_scale and fixed_frame_rate_flag
    /// are present in the bitstream
    timing_info_present_flag: bool,
    /* if timing_info_present_flag */
    /// The number of time units of a clock operating at the frequency
    /// time_scale Hz that corresponds to one increment (called a clock tick) of
    /// a clock tick counter
    num_units_in_tick: u32,
    /// The number of time units that pass in one second. For example, a time
    /// coordinate system that measures time using a 27 MHz clock has a
    /// time_scale of 27 000 000. time_scale shall be greater than 0.
    time_scale: u32,
    /// Retains the same meaning as the specification.
    fixed_frame_rate_flag: bool,

    /// Specifies that NAL HRD parameters (pertaining to Type II bitstream
    /// conformance) are present.
    nal_hrd_parameters_present_flag: bool,
    /* if nal_hrd_parameters_present_flag */
    /// The NAL HDR parameters
    nal_hrd_parameters: HrdParams,
    /// Specifies that VCL HRD parameters (pertaining to all bitstream
    /// conformance) are present.
    vcl_hrd_parameters_present_flag: bool,
    /* if vcl_hrd_parameters_present_flag */
    /// The VCL HRD parameters
    vcl_hrd_parameters: HrdParams,

    /// Specifies the HRD operational mode as specified in Annex C.
    low_delay_hrd_flag: bool,

    /// Specifies that picture timing SEI messages (clause D.2.3) are present
    /// that include the pic_struct syntax element.
    pic_struct_present_flag: bool,

    /// Specifies that the following coded video sequence bitstream restriction
    /// parameters are present
    bitstream_restriction_flag: bool,
    /*  if bitstream_restriction_flag */
    /// If false, indicates that no sample outside the picture boundaries and no
    /// sample at a fractional sample position for which the sample value is
    /// derived using one or more samples outside the picture boundaries is used
    /// for inter prediction of any sample. If true, indicates that one or more
    /// samples outside picture boundaries may be used in inter prediction. When
    /// the motion_vectors_over_pic_boundaries_flag syntax element is not
    /// present, motion_vectors_over_pic_boundaries_flag value shall be inferred
    /// to be true.
    motion_vectors_over_pic_boundaries_flag: bool,
    /// Indicates a number of bytes not exceeded by the sum of the sizes of the
    /// VCL NAL units associated with any coded picture in the coded video
    /// sequence.
    max_bytes_per_pic_denom: u32,
    /// Indicates an upper bound for the number of coded bits of
    /// macroblock_layer( ) data for any macroblock in any picture of the coded
    /// video sequence
    max_bits_per_mb_denom: u32,
    /// Retains the same meaning as the specification.
    log2_max_mv_length_horizontal: u32,
    /// Retains the same meaning as the specification.
    log2_max_mv_length_vertical: u32,
    /// Indicates an upper bound for the number of frames buffers, in the
    /// decoded picture buffer (DPB), that are required for storing frames,
    /// complementary field pairs, and non-paired fields before output. It is a
    /// requirement of bitstream conformance that the maximum number of frames,
    /// complementary field pairs, or non-paired fields that precede any frame,
    /// complementary field pair, or non-paired field in the coded video
    /// sequence in decoding order and follow it in output order shall be less
    /// than or equal to max_num_reorder_frames. The value of
    /// max_num_reorder_frames shall be in the range of 0 to
    /// max_dec_frame_buffering, inclusive.
    ///
    /// When the max_num_reorder_frames syntax element is not present, the value
    /// of max_num_reorder_frames value shall be inferred as follows:
    /// If profile_idc is equal to 44, 86, 100, 110, 122, or 244 and
    /// constraint_set3_flag is equal to 1, the value of max_num_reorder_frames
    /// shall be inferred to be equal to 0.
    ///
    /// Otherwise (profile_idc is not equal to 44, 86, 100, 110, 122, or 244 or
    /// constraint_set3_flag is equal to 0), the value of max_num_reorder_frames
    /// shall be inferred to be equal to MaxDpbFrames.
    max_num_reorder_frames: u32,
    /// Specifies the required size of the HRD decoded picture buffer (DPB) in
    /// units of frame buffers. It is a requirement of bitstream conformance
    /// that the coded video sequence shall not require a decoded picture buffer
    /// with size of more than Max( 1, max_dec_frame_buffering ) frame buffers
    /// to enable the output of decoded pictures at the output times specified
    /// by dpb_output_delay of the picture timing SEI messages. The value of
    /// max_dec_frame_buffering shall be greater than or equal to
    /// max_num_ref_frames. An upper bound for the value of
    /// max_dec_frame_buffering is specified by the level limits in clauses
    /// A.3.1, A.3.2, G.10.2.1, and H.10.2.
    ///
    /// When the max_dec_frame_buffering syntax element is not present, the
    /// value of max_dec_frame_buffering shall be inferred as follows:
    ///
    /// If profile_idc is equal to 44, 86, 100, 110, 122, or 244 and
    /// constraint_set3_flag is equal to 1, the value of max_dec_frame_buffering
    /// shall be inferred to be equal to 0.
    ///
    /// Otherwise (profile_idc is not equal to 44, 86, 100, 110, 122, or 244 or
    /// constraint_set3_flag is equal to 0), the value of
    /// max_dec_frame_buffering shall be inferred to be equal to MaxDpbFrames.
    max_dec_frame_buffering: u32,
}

impl VuiParams {
    pub fn aspect_ratio_info_present_flag(&self) -> bool {
        self.aspect_ratio_info_present_flag
    }
    pub fn aspect_ratio_idc(&self) -> u8 {
        self.aspect_ratio_idc
    }
    pub fn sar_width(&self) -> u16 {
        self.sar_width
    }
    pub fn sar_height(&self) -> u16 {
        self.sar_height
    }
    pub fn overscan_info_present_flag(&self) -> bool {
        self.overscan_info_present_flag
    }
    pub fn overscan_appropriate_flag(&self) -> bool {
        self.overscan_appropriate_flag
    }
    pub fn video_signal_type_present_flag(&self) -> bool {
        self.video_signal_type_present_flag
    }
    pub fn video_format(&self) -> u8 {
        self.video_format
    }
    pub fn video_full_range_flag(&self) -> bool {
        self.video_full_range_flag
    }
    pub fn colour_description_present_flag(&self) -> bool {
        self.colour_description_present_flag
    }
    pub fn colour_primaries(&self) -> u8 {
        self.colour_primaries
    }
    pub fn transfer_characteristics(&self) -> u8 {
        self.transfer_characteristics
    }
    pub fn matrix_coefficients(&self) -> u8 {
        self.matrix_coefficients
    }
    pub fn chroma_loc_info_present_flag(&self) -> bool {
        self.chroma_loc_info_present_flag
    }
    pub fn chroma_sample_loc_type_top_field(&self) -> u8 {
        self.chroma_sample_loc_type_top_field
    }
    pub fn chroma_sample_loc_type_bottom_field(&self) -> u8 {
        self.chroma_sample_loc_type_bottom_field
    }
    pub fn timing_info_present_flag(&self) -> bool {
        self.timing_info_present_flag
    }
    pub fn num_units_in_tick(&self) -> u32 {
        self.num_units_in_tick
    }
    pub fn time_scale(&self) -> u32 {
        self.time_scale
    }
    pub fn fixed_frame_rate_flag(&self) -> bool {
        self.fixed_frame_rate_flag
    }
    pub fn nal_hrd_parameters_present_flag(&self) -> bool {
        self.nal_hrd_parameters_present_flag
    }
    pub fn nal_hrd_parameters(&self) -> &HrdParams {
        &self.nal_hrd_parameters
    }
    pub fn vcl_hrd_parameters_present_flag(&self) -> bool {
        self.vcl_hrd_parameters_present_flag
    }
    pub fn vcl_hrd_parameters(&self) -> &HrdParams {
        &self.vcl_hrd_parameters
    }
    pub fn low_delay_hrd_flag(&self) -> bool {
        self.low_delay_hrd_flag
    }
    pub fn pic_struct_present_flag(&self) -> bool {
        self.pic_struct_present_flag
    }
    pub fn bitstream_restriction_flag(&self) -> bool {
        self.bitstream_restriction_flag
    }
    pub fn motion_vectors_over_pic_boundaries_flag(&self) -> bool {
        self.motion_vectors_over_pic_boundaries_flag
    }
    pub fn max_bytes_per_pic_denom(&self) -> u32 {
        self.max_bytes_per_pic_denom
    }
    pub fn max_bits_per_mb_denom(&self) -> u32 {
        self.max_bits_per_mb_denom
    }
    pub fn log2_max_mv_length_horizontal(&self) -> u32 {
        self.log2_max_mv_length_horizontal
    }
    pub fn log2_max_mv_length_vertical(&self) -> u32 {
        self.log2_max_mv_length_vertical
    }
    pub fn max_num_reorder_frames(&self) -> u32 {
        self.max_num_reorder_frames
    }
    pub fn max_dec_frame_buffering(&self) -> u32 {
        self.max_dec_frame_buffering
    }
}

impl Default for VuiParams {
    fn default() -> Self {
        Self {
            aspect_ratio_info_present_flag: Default::default(),
            aspect_ratio_idc: Default::default(),
            sar_width: Default::default(),
            sar_height: Default::default(),
            overscan_info_present_flag: Default::default(),
            overscan_appropriate_flag: Default::default(),
            video_signal_type_present_flag: Default::default(),
            video_format: 5,
            video_full_range_flag: Default::default(),
            colour_description_present_flag: Default::default(),
            colour_primaries: 2,
            transfer_characteristics: 2,
            matrix_coefficients: 2,
            chroma_loc_info_present_flag: Default::default(),
            chroma_sample_loc_type_top_field: Default::default(),
            chroma_sample_loc_type_bottom_field: Default::default(),
            timing_info_present_flag: Default::default(),
            num_units_in_tick: Default::default(),
            time_scale: Default::default(),
            fixed_frame_rate_flag: Default::default(),
            nal_hrd_parameters_present_flag: Default::default(),
            nal_hrd_parameters: Default::default(),
            vcl_hrd_parameters_present_flag: Default::default(),
            vcl_hrd_parameters: Default::default(),
            low_delay_hrd_flag: Default::default(),
            pic_struct_present_flag: Default::default(),
            bitstream_restriction_flag: Default::default(),
            motion_vectors_over_pic_boundaries_flag: Default::default(),
            max_bytes_per_pic_denom: Default::default(),
            max_bits_per_mb_denom: Default::default(),
            log2_max_mv_length_horizontal: Default::default(),
            log2_max_mv_length_vertical: Default::default(),
            max_num_reorder_frames: Default::default(),
            max_dec_frame_buffering: Default::default(),
        }
    }
}

/// A H264 Picture Parameter Set. A syntax structure containing syntax elements
/// that apply to zero or more entire coded pictures as determined by the
/// `pic_parameter_set_id` syntax element found in each slice header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pps {
    /// Identifies the picture parameter set that is referred to in the slice header.
    pic_parameter_set_id: u8,

    /// Refers to the active sequence parameter set.
    seq_parameter_set_id: u8,

    /// Selects the entropy decoding method to be applied for the syntax
    /// elements for which two descriptors appear in the syntax tables as
    /// follows: If `entropy_coding_mode_flag` is false, the method specified by
    /// the left descriptor in the syntax table is applied (Exp-Golomb coded,
    /// see clause 9.1 or CAVLC, see clause 9.2). Otherwise
    /// (`entropy_coding_mode_flag` is true), the method specified by the right
    /// descriptor in the syntax table is applied (CABAC, see clause 9.3).
    entropy_coding_mode_flag: bool,

    /// If true, specifies that the syntax elements delta_pic_order_cnt_bottom
    /// (when `pic_order_cnt_type` is equal to 0) or `delta_pic_order_cnt[1]`
    /// (when `pic_order_cnt_type` is equal to 1), which are related to picture
    /// order counts for the bottom field of a coded frame, are present in the
    /// slice headers for coded frames as specified in clause 7.3.3. Otherwise,
    /// specifies that the syntax elements `delta_pic_order_cnt_bottom` and
    /// `delta_pic_order_cnt[1]` are not present in the slice headers.
    bottom_field_pic_order_in_frame_present_flag: bool,

    /// Plus 1 specifies the number of slice groups for a picture. When
    /// `num_slice_groups_minus1` is equal to 0, all slices of the picture
    /// belong to the same slice group. The allowed range of
    /// `num_slice_groups_minus1` is specified in Annex A.
    num_slice_groups_minus1: u32,

    /// Specifies how `num_ref_idx_l0_active_minus1` is inferred for P, SP, and
    /// B slices with `num_ref_idx_active_override_flag` not set.
    num_ref_idx_l0_default_active_minus1: u8,

    /// Specifies how `num_ref_idx_l1_active_minus1` is inferred for B slices
    /// with `num_ref_idx_active_override_flag` not set.
    num_ref_idx_l1_default_active_minus1: u8,

    /// If not set, specifies that the default weighted prediction shall be
    /// applied to P and SP slices. If set, specifies that explicit weighted
    /// prediction shall be applied to P and SP slices.
    weighted_pred_flag: bool,

    /// `weighted_bipred_idc` equal to 0 specifies that the default weighted
    /// prediction shall be applied to B slices. `weighted_bipred_idc` equal to
    /// 1 specifies that explicit weighted prediction shall be applied to B
    /// slices. `weighted_bipred_idc` equal to 2 specifies that implicit
    /// weighted prediction shall be applied to B slices
    weighted_bipred_idc: u8,

    /// Specifies the initial value minus 26 of SliceQPY for each slice. The
    /// initial value is modified at the slice layer when a non-zero value of
    /// `slice_qp_delta` is decoded, and is modified further when a non-zero
    /// value of `mb_qp_delta` is decoded at the macroblock layer.
    pic_init_qp_minus26: i8,

    /// Specifies the initial value minus 26 of SliceQSY for all macroblocks in
    /// SP or SI slices. The initial value is modified at the slice layer when a
    /// non-zero value of `slice_qs_delta` is decoded.
    pic_init_qs_minus26: i8,

    /// Specifies the offset that shall be added to QP Y and QSY for addressing
    /// the table of QPC values for the Cb chroma component.
    chroma_qp_index_offset: i8,

    /// If set, specifies that a set of syntax elements controlling the
    /// characteristics of the deblocking filter is present in the slice header.
    /// If not set, specifies that the set of syntax elements controlling the
    /// characteristics of the deblocking filter is not present in the slice
    /// headers and their inferred values are in effect.
    deblocking_filter_control_present_flag: bool,

    /// If not set, specifies that intra prediction allows usage of residual
    /// data and decoded samples of neighbouring macroblocks coded using Inter
    /// macroblock prediction modes for the prediction of macroblocks coded
    /// using Intra macroblock prediction modes. If set, specifies constrained
    /// intra prediction, in which case prediction of macroblocks coded using
    /// Intra macroblock prediction modes only uses residual data and decoded
    /// samples from I or SI macroblock types.
    constrained_intra_pred_flag: bool,

    /// If not set, specifies that the `redundant_pic_cnt` syntax element is not
    /// present in slice headers, coded slice data partition B NAL units, and
    /// coded slice data partition C NAL units that refer (either directly or by
    /// association with a corresponding coded slice data partition A NAL unit)
    /// to the picture parameter set. If set, specifies that the
    /// `redundant_pic_cnt` syntax element is present in all slice headers,
    /// coded slice data partition B NAL units, and coded slice data partition C
    /// NAL units that refer (either directly or by association with a
    /// corresponding coded slice data partition A NAL unit) to the picture
    /// parameter set.
    redundant_pic_cnt_present_flag: bool,

    /// If set, specifies that the 8x8 transform decoding process may be in use
    /// (see clause 8.5). If not set, specifies that the 8x8 transform decoding
    /// process is not in use.
    transform_8x8_mode_flag: bool,

    ///  If set, specifies that parameters are present to modify the scaling
    ///  lists specified in the sequence parameter set. If not set, specifies
    ///  that the scaling lists used for the picture shall be inferred to be
    ///  equal to those specified by the sequence parameter set.
    pic_scaling_matrix_present_flag: bool,

    /// 4x4 Scaling list as read with 7.3.2.1.1.1
    scaling_lists_4x4: [[u8; 16]; 6],
    /// 8x8 Scaling list as read with 7.3.2.1.1.1
    scaling_lists_8x8: [[u8; 64]; 6],

    /// Specifies the offset that shall be added to QPY and QSY for addressing
    /// the table of QPC values for the Cr chroma component. When
    /// `second_chroma_qp_index_offset` is not present, it shall be inferred to be
    /// equal to `chroma_qp_index_offset`.
    second_chroma_qp_index_offset: i8,
}

impl Pps {
    pub fn pic_parameter_set_id(&self) -> u8 {
        self.pic_parameter_set_id
    }
    pub fn seq_parameter_set_id(&self) -> u8 {
        self.seq_parameter_set_id
    }
    pub fn entropy_coding_mode_flag(&self) -> bool {
        self.entropy_coding_mode_flag
    }
    pub fn bottom_field_pic_order_in_frame_present_flag(&self) -> bool {
        self.bottom_field_pic_order_in_frame_present_flag
    }
    pub fn num_slice_groups_minus1(&self) -> u32 {
        self.num_slice_groups_minus1
    }
    pub fn num_ref_idx_l0_default_active_minus1(&self) -> u8 {
        self.num_ref_idx_l0_default_active_minus1
    }
    pub fn num_ref_idx_l1_default_active_minus1(&self) -> u8 {
        self.num_ref_idx_l1_default_active_minus1
    }
    pub fn weighted_pred_flag(&self) -> bool {
        self.weighted_pred_flag
    }
    pub fn weighted_bipred_idc(&self) -> u8 {
        self.weighted_bipred_idc
    }
    pub fn pic_init_qp_minus26(&self) -> i8 {
        self.pic_init_qp_minus26
    }
    pub fn pic_init_qs_minus26(&self) -> i8 {
        self.pic_init_qs_minus26
    }
    pub fn chroma_qp_index_offset(&self) -> i8 {
        self.chroma_qp_index_offset
    }
    pub fn deblocking_filter_control_present_flag(&self) -> bool {
        self.deblocking_filter_control_present_flag
    }
    pub fn constrained_intra_pred_flag(&self) -> bool {
        self.constrained_intra_pred_flag
    }
    pub fn redundant_pic_cnt_present_flag(&self) -> bool {
        self.redundant_pic_cnt_present_flag
    }
    pub fn transform_8x8_mode_flag(&self) -> bool {
        self.transform_8x8_mode_flag
    }
    pub fn pic_scaling_matrix_present_flag(&self) -> bool {
        self.pic_scaling_matrix_present_flag
    }
    pub fn scaling_lists_4x4(&self) -> [[u8; 16]; 6] {
        self.scaling_lists_4x4
    }
    pub fn scaling_lists_8x8(&self) -> [[u8; 64]; 6] {
        self.scaling_lists_8x8
    }
    pub fn second_chroma_qp_index_offset(&self) -> i8 {
        self.second_chroma_qp_index_offset
    }
}

impl Default for Pps {
    fn default() -> Self {
        Self {
            scaling_lists_4x4: [[0; 16]; 6],
            scaling_lists_8x8: [[0; 64]; 6],
            pic_parameter_set_id: Default::default(),
            seq_parameter_set_id: Default::default(),
            entropy_coding_mode_flag: Default::default(),
            bottom_field_pic_order_in_frame_present_flag: Default::default(),
            num_slice_groups_minus1: Default::default(),
            num_ref_idx_l0_default_active_minus1: Default::default(),
            num_ref_idx_l1_default_active_minus1: Default::default(),
            weighted_pred_flag: Default::default(),
            weighted_bipred_idc: Default::default(),
            pic_init_qp_minus26: Default::default(),
            pic_init_qs_minus26: Default::default(),
            chroma_qp_index_offset: Default::default(),
            deblocking_filter_control_present_flag: Default::default(),
            constrained_intra_pred_flag: Default::default(),
            redundant_pic_cnt_present_flag: Default::default(),
            transform_8x8_mode_flag: Default::default(),
            second_chroma_qp_index_offset: Default::default(),
            pic_scaling_matrix_present_flag: Default::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Parser {
    active_spses: BTreeMap<u8, Sps>,
    active_ppses: BTreeMap<u8, Pps>,
}

impl Parser {
    fn fill_default_scaling_list_4x4(scaling_list4x4: &mut [u8; 16], i: usize) {
        // See table 7.2 in the spec.
        assert!(i < 6);
        if i < 3 {
            *scaling_list4x4 = DEFAULT_4X4_INTRA;
        } else if i < 6 {
            *scaling_list4x4 = DEFAULT_4X4_INTER;
        }
    }

    fn fill_default_scaling_list_8x8(scaling_list8x8: &mut [u8; 64], i: usize) {
        assert!(i < 6);
        if i % 2 == 0 {
            *scaling_list8x8 = DEFAULT_8X8_INTRA;
        } else {
            *scaling_list8x8 = DEFAULT_8X8_INTER;
        }
    }

    fn fill_fallback_scaling_list_4x4(
        scaling_list4x4: &mut [[u8; 16]; 6],
        i: usize,
        default_scaling_list_intra: &[u8; 16],
        default_scaling_list_inter: &[u8; 16],
    ) {
        // See table 7.2 in the spec.
        scaling_list4x4[i] = match i {
            0 => *default_scaling_list_intra,
            1 => scaling_list4x4[0],
            2 => scaling_list4x4[1],
            3 => *default_scaling_list_inter,
            4 => scaling_list4x4[3],
            5 => scaling_list4x4[4],
            _ => panic!("Unexpected value {}", i),
        }
    }

    fn fill_fallback_scaling_list_8x8(
        scaling_list8x8: &mut [[u8; 64]; 6],
        i: usize,
        default_scaling_list_intra: &[u8; 64],
        default_scaling_list_inter: &[u8; 64],
    ) {
        // See table 7.2 in the spec.
        scaling_list8x8[i] = match i {
            0 => *default_scaling_list_intra,
            1 => *default_scaling_list_inter,
            2 => scaling_list8x8[0],
            3 => scaling_list8x8[1],
            4 => scaling_list8x8[2],
            5 => scaling_list8x8[3],
            _ => panic!("Unexpected value {}", i),
        }
    }

    fn fill_scaling_list_flat(
        scaling_list4x4: &mut [[u8; 16]; 6],
        scaling_list8x8: &mut [[u8; 64]; 6],
    ) {
        // (7-8) in the spec.
        for outer in scaling_list4x4 {
            for inner in outer {
                *inner = 16;
            }
        }

        // (7-9) in the spec.
        for outer in scaling_list8x8 {
            for inner in outer {
                *inner = 16;
            }
        }
    }

    fn parse_scaling_list<T: AsRef<[u8]>, U: AsMut<[u8]>>(
        r: &mut NaluReader<T>,
        scaling_list: &mut U,
        use_default: &mut bool,
    ) -> Result<()> {
        // 7.3.2.1.1.1
        let mut last_scale = 8;
        let mut next_scale = 8;

        for j in 0..scaling_list.as_mut().len() {
            if next_scale != 0 {
                let delta_scale = r.read_se::<i32>()?;
                next_scale = (last_scale + delta_scale + 256) % 256;
                *use_default = j == 0 && next_scale == 0;
                if *use_default {
                    return Ok(());
                }
            }

            scaling_list.as_mut()[j] = if next_scale == 0 {
                u8::try_from(last_scale)?
            } else {
                u8::try_from(next_scale)?
            };

            last_scale = i32::from(scaling_list.as_mut()[j]);
        }

        Ok(())
    }

    fn parse_sps_scaling_lists<T: AsRef<[u8]>>(r: &mut NaluReader<T>, sps: &mut Sps) -> Result<()> {
        let scaling_lists4x4 = &mut sps.scaling_lists_4x4;
        let scaling_lisst8x8 = &mut sps.scaling_lists_8x8;

        // Parse scaling_list4x4
        for i in 0..6 {
            let seq_scaling_list_present_flag = r.read_bit()?;
            if seq_scaling_list_present_flag {
                let mut use_default = false;

                Parser::parse_scaling_list(r, &mut scaling_lists4x4[i], &mut use_default)?;

                if use_default {
                    Parser::fill_default_scaling_list_4x4(&mut scaling_lists4x4[i], i);
                }
            } else {
                Parser::fill_fallback_scaling_list_4x4(
                    scaling_lists4x4,
                    i,
                    &DEFAULT_4X4_INTRA,
                    &DEFAULT_4X4_INTER,
                );
            }
        }

        // Parse scaling_list8x8
        let num_8x8 = if sps.chroma_format_idc != 3 { 2 } else { 6 };
        for i in 0..num_8x8 {
            let seq_scaling_list_present_flag = r.read_bit()?;
            if seq_scaling_list_present_flag {
                let mut use_default = false;
                Parser::parse_scaling_list(r, &mut scaling_lisst8x8[i], &mut use_default)?;

                if use_default {
                    Parser::fill_default_scaling_list_8x8(&mut scaling_lisst8x8[i], i);
                }
            } else {
                Parser::fill_fallback_scaling_list_8x8(
                    scaling_lisst8x8,
                    i,
                    &DEFAULT_8X8_INTRA,
                    &DEFAULT_8X8_INTER,
                );
            }
        }
        Ok(())
    }

    fn parse_pps_scaling_lists<T: AsRef<[u8]>>(
        r: &mut NaluReader<T>,
        pps: &mut Pps,
        sps: &Sps,
    ) -> Result<()> {
        let scaling_lists4x4 = &mut pps.scaling_lists_4x4;
        let scaling_lists8x8 = &mut pps.scaling_lists_8x8;

        for i in 0..6 {
            let pic_scaling_list_present_flag = r.read_bit()?;
            if pic_scaling_list_present_flag {
                let mut use_default = false;

                Parser::parse_scaling_list(r, &mut scaling_lists4x4[i], &mut use_default)?;

                if use_default {
                    Parser::fill_default_scaling_list_4x4(&mut scaling_lists4x4[i], i);
                }
            } else if !sps.seq_scaling_matrix_present_flag {
                // Table 7-2: Fallback rule A
                Parser::fill_fallback_scaling_list_4x4(
                    scaling_lists4x4,
                    i,
                    &DEFAULT_4X4_INTRA,
                    &DEFAULT_4X4_INTER,
                );
            } else {
                // Table 7-2: Fallback rule B
                Parser::fill_fallback_scaling_list_4x4(
                    scaling_lists4x4,
                    i,
                    &sps.scaling_lists_4x4[0],
                    &sps.scaling_lists_4x4[3],
                );
            }
        }

        if pps.transform_8x8_mode_flag {
            let num8x8 = if sps.chroma_format_idc != 3 { 2 } else { 6 };

            for i in 0..num8x8 {
                let pic_scaling_list_present_flag = r.read_bit()?;
                if pic_scaling_list_present_flag {
                    let mut use_default = false;

                    Parser::parse_scaling_list(r, &mut scaling_lists8x8[i], &mut use_default)?;

                    if use_default {
                        Parser::fill_default_scaling_list_4x4(&mut scaling_lists4x4[i], i);
                    }
                } else if !sps.seq_scaling_matrix_present_flag {
                    // Table 7-2: Fallback rule A
                    Parser::fill_fallback_scaling_list_8x8(
                        scaling_lists8x8,
                        i,
                        &DEFAULT_8X8_INTRA,
                        &DEFAULT_8X8_INTER,
                    );
                } else {
                    // Table 7-2: Fallback rule B
                    Parser::fill_fallback_scaling_list_8x8(
                        scaling_lists8x8,
                        i,
                        &sps.scaling_lists_8x8[0],
                        &sps.scaling_lists_8x8[1],
                    );
                }
            }
        }

        Ok(())
    }

    pub fn parse_hrd<T: AsRef<[u8]>>(r: &mut NaluReader<T>, hrd: &mut HrdParams) -> Result<()> {
        hrd.cpb_cnt_minus1 = r.read_ue_max(31)?;
        hrd.bit_rate_scale = r.read_bits(4)?;
        hrd.cpb_size_scale = r.read_bits(4)?;

        for sched_sel_idx in 0..=usize::from(hrd.cpb_cnt_minus1) {
            hrd.bit_rate_value_minus1[sched_sel_idx] = r.read_ue()?;
            hrd.cpb_size_value_minus1[sched_sel_idx] = r.read_ue()?;
            hrd.cbr_flag[sched_sel_idx] = r.read_bit()?;
        }

        hrd.initial_cpb_removal_delay_length_minus1 = r.read_bits(5)?;
        hrd.cpb_removal_delay_length_minus1 = r.read_bits(5)?;
        hrd.dpb_output_delay_length_minus1 = r.read_bits(5)?;
        hrd.time_offset_length = r.read_bits(5)?;
        Ok(())
    }

    pub fn parse_vui<T: AsRef<[u8]>>(r: &mut NaluReader<T>, sps: &mut Sps) -> Result<()> {
        let vui = &mut sps.vui_parameters;

        vui.aspect_ratio_info_present_flag = r.read_bit()?;
        if vui.aspect_ratio_info_present_flag {
            vui.aspect_ratio_idc = r.read_bits(8)?;
            if vui.aspect_ratio_idc == 255 {
                vui.sar_width = r.read_bits(16)?;
                vui.sar_height = r.read_bits(16)?;
            }
        }

        vui.overscan_info_present_flag = r.read_bit()?;
        if vui.overscan_info_present_flag {
            vui.overscan_appropriate_flag = r.read_bit()?;
        }

        vui.video_signal_type_present_flag = r.read_bit()?;
        if vui.video_signal_type_present_flag {
            vui.video_format = r.read_bits(3)?;
            vui.video_full_range_flag = r.read_bit()?;
            vui.colour_description_present_flag = r.read_bit()?;
            if vui.colour_description_present_flag {
                vui.colour_primaries = r.read_bits(8)?;
                vui.transfer_characteristics = r.read_bits(8)?;
                vui.matrix_coefficients = r.read_bits(8)?;
            }
        }

        vui.chroma_loc_info_present_flag = r.read_bit()?;
        if vui.chroma_loc_info_present_flag {
            vui.chroma_sample_loc_type_top_field = r.read_ue_max(5)?;
            vui.chroma_sample_loc_type_bottom_field = r.read_ue_max(5)?;
        }

        vui.timing_info_present_flag = r.read_bit()?;
        if vui.timing_info_present_flag {
            vui.num_units_in_tick = r.read_bits::<u32>(31)? << 1;
            vui.num_units_in_tick |= r.read_bit()? as u32;
            if vui.num_units_in_tick == 0 {
                return Err(anyhow!(
                    "num_units_in_tick == 0, which is not allowed by E.2.1"
                ));
            }

            vui.time_scale = r.read_bits::<u32>(31)? << 1;
            vui.time_scale |= r.read_bit()? as u32;
            if vui.time_scale == 0 {
                return Err(anyhow!("time_scale == 0, which is not allowed by E.2.1"));
            }

            vui.fixed_frame_rate_flag = r.read_bit()?;
        }

        vui.nal_hrd_parameters_present_flag = r.read_bit()?;
        if vui.nal_hrd_parameters_present_flag {
            Parser::parse_hrd(r, &mut vui.nal_hrd_parameters)?;
        }

        vui.vcl_hrd_parameters_present_flag = r.read_bit()?;
        if vui.vcl_hrd_parameters_present_flag {
            Parser::parse_hrd(r, &mut vui.vcl_hrd_parameters)?;
        }

        if vui.nal_hrd_parameters_present_flag || vui.vcl_hrd_parameters_present_flag {
            vui.low_delay_hrd_flag = r.read_bit()?;
        }

        vui.pic_struct_present_flag = r.read_bit()?;
        vui.bitstream_restriction_flag = r.read_bit()?;

        if vui.bitstream_restriction_flag {
            vui.motion_vectors_over_pic_boundaries_flag = r.read_bit()?;
            vui.max_bytes_per_pic_denom = r.read_ue()?;
            vui.max_bits_per_mb_denom = r.read_ue_max(16)?;
            vui.log2_max_mv_length_horizontal = r.read_ue_max(16)?;
            vui.log2_max_mv_length_vertical = r.read_ue_max(16)?;
            vui.max_num_reorder_frames = r.read_ue()?;
            vui.max_dec_frame_buffering = r.read_ue()?;
        }

        Ok(())
    }

    pub fn parse_sps<T: AsRef<[u8]>>(&mut self, nalu: &Nalu<T>) -> Result<&Sps> {
        let data = nalu.as_ref();
        // Skip the header
        let mut r = NaluReader::new(&data[nalu.header.header_bytes..]);
        let mut sps = Sps {
            profile_idc: r.read_bits(8)?,
            constraint_set0_flag: r.read_bit()?,
            constraint_set1_flag: r.read_bit()?,
            constraint_set2_flag: r.read_bit()?,
            constraint_set3_flag: r.read_bit()?,
            constraint_set4_flag: r.read_bit()?,
            constraint_set5_flag: r.read_bit()?,
            ..Default::default()
        };

        // skip reserved_zero_2bits
        r.skip_bits(2)?;

        let level: u8 = r.read_bits(8)?;
        sps.level_idc = Level::n(level).with_context(|| format!("Unsupported level {}", level))?;
        sps.seq_parameter_set_id = r.read_ue_max(31)?;

        if sps.profile_idc == 100
            || sps.profile_idc == 110
            || sps.profile_idc == 122
            || sps.profile_idc == 244
            || sps.profile_idc == 44
            || sps.profile_idc == 83
            || sps.profile_idc == 86
            || sps.profile_idc == 118
            || sps.profile_idc == 128
            || sps.profile_idc == 138
            || sps.profile_idc == 139
            || sps.profile_idc == 134
            || sps.profile_idc == 135
        {
            sps.chroma_format_idc = r.read_ue_max(3)?;
            if sps.chroma_format_idc == 3 {
                sps.separate_colour_plane_flag = r.read_bit()?;
            }

            sps.bit_depth_luma_minus8 = r.read_ue_max(6)?;
            sps.bit_depth_chroma_minus8 = r.read_ue_max(6)?;
            sps.qpprime_y_zero_transform_bypass_flag = r.read_bit()?;
            sps.seq_scaling_matrix_present_flag = r.read_bit()?;

            if sps.seq_scaling_matrix_present_flag {
                Parser::parse_sps_scaling_lists(&mut r, &mut sps)?;
            } else {
                Parser::fill_scaling_list_flat(
                    &mut sps.scaling_lists_4x4,
                    &mut sps.scaling_lists_8x8,
                );
            }
        } else {
            sps.chroma_format_idc = 1;
            Parser::fill_scaling_list_flat(&mut sps.scaling_lists_4x4, &mut sps.scaling_lists_8x8);
        }

        if sps.separate_colour_plane_flag {
            sps.chroma_array_type = 0;
        } else {
            sps.chroma_array_type = sps.chroma_format_idc;
        }

        sps.log2_max_frame_num_minus4 = r.read_ue_max(12)?;
        sps.max_frame_num = 1 << (sps.log2_max_frame_num_minus4 + 4);

        sps.pic_order_cnt_type = r.read_ue_max(2)?;

        if sps.pic_order_cnt_type == 0 {
            sps.log2_max_pic_order_cnt_lsb_minus4 = r.read_ue_max(12)?;
            sps.expected_delta_per_pic_order_cnt_cycle = 0;
        } else if sps.pic_order_cnt_type == 1 {
            sps.delta_pic_order_always_zero_flag = r.read_bit()?;
            sps.offset_for_non_ref_pic = r.read_se()?;
            sps.offset_for_top_to_bottom_field = r.read_se()?;
            sps.num_ref_frames_in_pic_order_cnt_cycle = r.read_ue_max(254)?;

            let mut offset_acc = 0;
            for i in 0..usize::from(sps.num_ref_frames_in_pic_order_cnt_cycle) {
                sps.offset_for_ref_frame[i] = r.read_se()?;

                // (7-12) in the spec.
                offset_acc += sps.offset_for_ref_frame[i];
            }

            sps.expected_delta_per_pic_order_cnt_cycle = offset_acc;
        }

        sps.max_num_ref_frames = r.read_ue()?;
        sps.gaps_in_frame_num_value_allowed_flag = r.read_bit()?;
        sps.pic_width_in_mbs_minus1 = r.read_ue()?;
        sps.pic_height_in_map_units_minus1 = r.read_ue()?;
        sps.frame_mbs_only_flag = r.read_bit()?;

        if !sps.frame_mbs_only_flag {
            sps.mb_adaptive_frame_field_flag = r.read_bit()?;
        }

        sps.direct_8x8_inference_flag = r.read_bit()?;
        sps.frame_cropping_flag = r.read_bit()?;

        if sps.frame_cropping_flag {
            sps.frame_crop_left_offset = r.read_ue()?;
            sps.frame_crop_right_offset = r.read_ue()?;
            sps.frame_crop_top_offset = r.read_ue()?;
            sps.frame_crop_bottom_offset = r.read_ue()?;
        }

        sps.vui_parameters_present_flag = r.read_bit()?;
        if sps.vui_parameters_present_flag {
            Parser::parse_vui(&mut r, &mut sps)?;
        }

        let mut width = (sps.pic_width_in_mbs_minus1 + 1) * 16;
        let mut height = (sps.pic_height_in_map_units_minus1 + 1)
            * 16
            * (2 - u32::from(sps.frame_mbs_only_flag));

        sps.width = width;
        sps.height = height;

        if sps.frame_cropping_flag {
            // Table 6-1 in the spec.
            let sub_width_c = [1, 2, 2, 1];
            let sub_height_c = [1, 2, 1, 1];

            let crop_unit_x = sub_width_c[usize::from(sps.chroma_format_idc)];
            let crop_unit_y = sub_height_c[usize::from(sps.chroma_format_idc)]
                * (2 - u32::from(sps.frame_mbs_only_flag));

            width -= (sps.frame_crop_left_offset + sps.frame_crop_right_offset) * crop_unit_x;
            height -= (sps.frame_crop_top_offset + sps.frame_crop_bottom_offset) * crop_unit_y;

            sps.crop_rect_width = width;
            sps.crop_rect_height = height;
            sps.crop_rect_x = sps.frame_crop_left_offset * crop_unit_x;
            sps.crop_rect_y = sps.frame_crop_top_offset * crop_unit_y;
        }

        let key = sps.seq_parameter_set_id;
        self.active_spses.insert(key, sps);

        if self.active_spses.keys().len() > MAX_SPS_COUNT {
            return Err(anyhow!(
                "Broken data: Number of active SPSs > MAX_SPS_COUNT"
            ));
        }

        Ok(self.get_sps(key).unwrap())
    }

    pub fn parse_pps<T: AsRef<[u8]>>(&mut self, nalu: &Nalu<T>) -> Result<&Pps> {
        let data = nalu.as_ref();
        // Skip the header
        let mut r = NaluReader::new(&data[nalu.header.header_bytes..]);
        let mut pps = Pps {
            pic_parameter_set_id: r.read_ue_max(u32::try_from(MAX_PPS_COUNT)? - 1)?,
            seq_parameter_set_id: r.read_ue_max(u32::try_from(MAX_SPS_COUNT)? - 1)?,
            ..Default::default()
        };

        let sps = self.get_sps(pps.seq_parameter_set_id).context(
            "Broken stream: stream references a SPS that has not been successfully parsed",
        )?;

        pps.entropy_coding_mode_flag = r.read_bit()?;
        pps.bottom_field_pic_order_in_frame_present_flag = r.read_bit()?;
        pps.num_slice_groups_minus1 = r.read_ue_max(7)?;

        if pps.num_slice_groups_minus1 > 0 {
            return Err(anyhow!("Stream contain unsupported/unimplemented NALs"));
        }

        pps.num_ref_idx_l0_default_active_minus1 = r.read_ue_max(31)?;
        pps.num_ref_idx_l1_default_active_minus1 = r.read_ue_max(31)?;

        pps.weighted_pred_flag = r.read_bit()?;
        pps.weighted_bipred_idc = r.read_bits(2)?;

        let qp_bd_offset_y = i32::from(6 * (sps.bit_depth_luma_minus8));
        pps.pic_init_qp_minus26 = r.read_se_bounded(-(26 + qp_bd_offset_y), 25)?;
        pps.pic_init_qs_minus26 = r.read_se_bounded(-26, 25)?;

        pps.chroma_qp_index_offset = r.read_se_bounded(-12, 12)?;

        // When second_chroma_qp_index_offset is not present, it shall be
        // inferred to be equal to chroma_qp_index_offset.
        pps.second_chroma_qp_index_offset = pps.chroma_qp_index_offset;

        pps.deblocking_filter_control_present_flag = r.read_bit()?;
        pps.constrained_intra_pred_flag = r.read_bit()?;
        pps.redundant_pic_cnt_present_flag = r.read_bit()?;

        if r.has_more_rsbp_data() {
            pps.transform_8x8_mode_flag = r.read_bit()?;
            pps.pic_scaling_matrix_present_flag = r.read_bit()?;

            if pps.pic_scaling_matrix_present_flag {
                Parser::parse_pps_scaling_lists(&mut r, &mut pps, sps)?;
            }

            pps.second_chroma_qp_index_offset = r.read_se()?;
        }

        if !pps.pic_scaling_matrix_present_flag {
            // If not set, specifies that the scaling lists used for the picture
            // shall be inferred to be equal to those specified by the sequence
            // parameter set. When pic_scaling_matrix_present_flag is not
            // present, it shall be inferred to be not set.
            pps.scaling_lists_4x4 = sps.scaling_lists_4x4;
            pps.scaling_lists_8x8 = sps.scaling_lists_8x8;
        }

        let key = pps.pic_parameter_set_id;
        self.active_ppses.insert(key, pps);

        if self.active_ppses.keys().len() > MAX_PPS_COUNT {
            return Err(anyhow!(
                "Broken Data: number of active PPSs > MAX_PPS_COUNT"
            ));
        }

        Ok(self.get_pps(key).unwrap())
    }

    fn parse_ref_pic_list_modification<T: AsRef<[u8]>>(
        r: &mut NaluReader<T>,
        num_ref_idx_active_minus1: u8,
        ref_list_mods: &mut Vec<RefPicListModification>,
    ) -> Result<()> {
        if num_ref_idx_active_minus1 >= 32 {
            return Err(anyhow!("Broken Data: num_ref_idx_active_minus1 >= 32"));
        }

        loop {
            let mut pic_num_mod = RefPicListModification {
                modification_of_pic_nums_idc: r.read_ue_max(3)?,
                ..Default::default()
            };

            match pic_num_mod.modification_of_pic_nums_idc {
                0 | 1 => {
                    pic_num_mod.abs_diff_pic_num_minus1 = r.read_ue()?;
                }

                2 => {
                    pic_num_mod.long_term_pic_num = r.read_ue()?;
                }

                3 => {
                    ref_list_mods.push(pic_num_mod);
                    break;
                }

                _ => return Err(anyhow!("Broken Data: modification_of_pic_nums_idc > 3")),
            }

            ref_list_mods.push(pic_num_mod);
        }

        Ok(())
    }

    fn parse_ref_pic_list_modifications<T: AsRef<[u8]>>(
        r: &mut NaluReader<T>,
        header: &mut SliceHeader,
    ) -> Result<()> {
        if !header.slice_type.is_i() && !header.slice_type.is_si() {
            header.ref_pic_list_modification_flag_l0 = r.read_bit()?;
            if header.ref_pic_list_modification_flag_l0 {
                Parser::parse_ref_pic_list_modification(
                    r,
                    header.num_ref_idx_l0_active_minus1,
                    &mut header.ref_pic_list_modification_l0,
                )?;
            }
        }

        if header.slice_type.is_b() {
            header.ref_pic_list_modification_flag_l1 = r.read_bit()?;
            if header.ref_pic_list_modification_flag_l1 {
                Parser::parse_ref_pic_list_modification(
                    r,
                    header.num_ref_idx_l1_active_minus1,
                    &mut header.ref_pic_list_modification_l1,
                )?;
            }
        }

        Ok(())
    }

    fn parse_pred_weight_table<T: AsRef<[u8]>>(
        r: &mut NaluReader<T>,
        sps: &Sps,
        header: &mut SliceHeader,
    ) -> Result<()> {
        let pt = &mut header.pred_weight_table;
        pt.luma_log2_weight_denom = r.read_ue_max(7)?;

        // When luma_weight_l0_flag is equal to 0, luma_weight_l0[i] shall be
        // inferred to be equal to 2 ^ luma_log2_weight_denom for
        // RefPicList0[i].
        let default_luma_weight = 1 << pt.luma_log2_weight_denom;
        for i in 0..=header.num_ref_idx_l0_active_minus1 {
            pt.luma_weight_l0[usize::from(i)] = default_luma_weight;
        }

        // When luma_weight_l1_flag is equal to 1, luma_weight_l1[i] shall be
        // inferred to be equal to 2 ^ luma_log2_weight_denom for
        // RefPicList1[i].
        if header.slice_type.is_b() {
            for i in 0..=header.num_ref_idx_l1_active_minus1 {
                pt.luma_weight_l1[usize::from(i)] = default_luma_weight;
            }
        }

        if sps.chroma_array_type != 0 {
            pt.chroma_log2_weight_denom = r.read_ue_max(7)?;
            let default_chroma_weight = 1 << pt.chroma_log2_weight_denom;

            // When chroma_weight_l0_flag is equal to 0, chroma_weight_l0[i]
            // shall be inferred to be equal to 2 ^ chroma_log2_weight_denom for
            // RefPicList0[i].
            for i in 0..=header.num_ref_idx_l0_active_minus1 {
                pt.chroma_weight_l0[usize::from(i)][0] = default_chroma_weight;
                pt.chroma_weight_l0[usize::from(i)][1] = default_chroma_weight;
            }

            // When chroma_weight_l1_flag is equal to 0, chroma_weight_l1[i]
            // shall be inferred to be equal to 2 ^ chroma_log2_weight_denom for
            // RefPicList1[i].
            for i in 0..=header.num_ref_idx_l1_active_minus1 {
                pt.chroma_weight_l1[usize::from(i)][0] = default_chroma_weight;
                pt.chroma_weight_l1[usize::from(i)][1] = default_chroma_weight;
            }
        }

        for i in 0..=header.num_ref_idx_l0_active_minus1 {
            let luma_weight_l0_flag = r.read_bit()?;

            if luma_weight_l0_flag {
                pt.luma_weight_l0[usize::from(i)] = r.read_se_bounded(-128, 127)?;
                pt.luma_offset_l0[usize::from(i)] = r.read_se_bounded(-128, 127)?;
            }

            if sps.chroma_array_type != 0 {
                let chroma_weight_l0_flag = r.read_bit()?;
                if chroma_weight_l0_flag {
                    for j in 0..2 {
                        pt.chroma_weight_l0[usize::from(i)][j] = r.read_se_bounded(-128, 127)?;
                        pt.chroma_offset_l0[usize::from(i)][j] = r.read_se_bounded(-128, 127)?;
                    }
                }
            }
        }

        if header.slice_type.is_b() {
            for i in 0..=header.num_ref_idx_l1_active_minus1 {
                let luma_weight_l1_flag = r.read_bit()?;

                if luma_weight_l1_flag {
                    pt.luma_weight_l1[usize::from(i)] = r.read_se_bounded(-128, 127)?;
                    pt.luma_offset_l1[usize::from(i)] = r.read_se_bounded(-128, 127)?;
                }

                if sps.chroma_array_type != 0 {
                    let chroma_weight_l1_flag = r.read_bit()?;
                    if chroma_weight_l1_flag {
                        for j in 0..2 {
                            pt.chroma_weight_l1[usize::from(i)][j] =
                                r.read_se_bounded(-128, 127)?;
                            pt.chroma_offset_l1[usize::from(i)][j] =
                                r.read_se_bounded(-128, 127)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_dec_ref_pic_marking<T: AsRef<[u8]>, U: AsRef<[u8]>>(
        r: &mut NaluReader<T>,
        nalu: &Nalu<U>,
        header: &mut SliceHeader,
    ) -> Result<()> {
        let rpm = &mut header.dec_ref_pic_marking;

        if nalu.header.idr_pic_flag {
            rpm.no_output_of_prior_pics_flag = r.read_bit()?;
            rpm.long_term_reference_flag = r.read_bit()?;
        } else {
            rpm.adaptive_ref_pic_marking_mode_flag = r.read_bit()?;

            if rpm.adaptive_ref_pic_marking_mode_flag {
                loop {
                    let mut marking = RefPicMarkingInner::default();

                    let mem_mgmt_ctrl_op = r.read_ue_max::<u8>(6)?;
                    marking.memory_management_control_operation = mem_mgmt_ctrl_op;

                    if mem_mgmt_ctrl_op == 0 {
                        break;
                    }

                    if mem_mgmt_ctrl_op == 1 || mem_mgmt_ctrl_op == 3 {
                        marking.difference_of_pic_nums_minus1 = r.read_ue()?;
                    }

                    if mem_mgmt_ctrl_op == 2 {
                        marking.long_term_pic_num = r.read_ue()?;
                    }

                    if mem_mgmt_ctrl_op == 3 || mem_mgmt_ctrl_op == 6 {
                        marking.long_term_frame_idx = r.read_ue()?;
                    }

                    if mem_mgmt_ctrl_op == 4 {
                        marking.max_long_term_frame_idx_plus1 = r.read_ue()?;
                    }

                    rpm.inner.push(marking);
                }
            }
        }

        Ok(())
    }

    pub fn parse_slice_header<T: AsRef<[u8]>>(&mut self, nalu: Nalu<T>) -> Result<Slice<T>> {
        let data = nalu.as_ref();
        // Skip the header
        let mut r = NaluReader::new(&data[nalu.header.header_bytes..]);

        let mut header = SliceHeader {
            first_mb_in_slice: r.read_ue()?,
            ..Default::default()
        };

        let slice_type = r.read_ue_max::<u8>(9)? % 5;
        header.slice_type = SliceType::n(slice_type)
            .with_context(|| format!("Invalid slice type {}", slice_type))?;

        header.pic_parameter_set_id = r.read_ue()?;

        let pps = self.get_pps(header.pic_parameter_set_id).context(
            "Broken stream: slice references PPS that has not been successfully parsed.",
        )?;

        let sps = self.get_sps(pps.seq_parameter_set_id).context(
            "Broken stream: slice's PPS references SPS that has not been successfully parsed.",
        )?;

        if sps.separate_colour_plane_flag {
            header.colour_plane_id = r.read_bits(2)?;
        }

        header.frame_num = r.read_bits(usize::from(sps.log2_max_frame_num_minus4) + 4)?;

        if !sps.frame_mbs_only_flag {
            header.field_pic_flag = r.read_bit()?;
            if header.field_pic_flag {
                header.bottom_field_flag = r.read_bit()?;
            }
        }

        if header.field_pic_flag {
            header.max_pic_num = 2 * sps.max_frame_num;
        } else {
            header.max_pic_num = sps.max_frame_num;
        }

        if nalu.header.idr_pic_flag {
            header.idr_pic_id = r.read_ue_max(0xffff)?;
        }

        if sps.pic_order_cnt_type == 0 {
            header.pic_order_cnt_lsb =
                r.read_bits(usize::from(sps.log2_max_pic_order_cnt_lsb_minus4) + 4)?;

            if pps.bottom_field_pic_order_in_frame_present_flag && !header.field_pic_flag {
                header.delta_pic_order_cnt_bottom = r.read_se()?;
            }
        }

        if sps.pic_order_cnt_type == 1 && !sps.delta_pic_order_always_zero_flag {
            header.delta_pic_order_cnt[0] = r.read_se()?;
            if pps.bottom_field_pic_order_in_frame_present_flag && !header.field_pic_flag {
                header.delta_pic_order_cnt[1] = r.read_se()?;
            }
        }

        if pps.redundant_pic_cnt_present_flag {
            header.redundant_pic_cnt = r.read_ue_max(127)?;
        }

        if header.slice_type.is_b() {
            header.direct_spatial_mv_pred_flag = r.read_bit()?;
        }

        if header.slice_type.is_p() || header.slice_type.is_sp() || header.slice_type.is_b() {
            header.num_ref_idx_active_override_flag = r.read_bit()?;
            if header.num_ref_idx_active_override_flag {
                header.num_ref_idx_l0_active_minus1 = r.read_ue()?;
                if header.slice_type.is_b() {
                    header.num_ref_idx_l1_active_minus1 = r.read_ue()?;
                }
            } else {
                header.num_ref_idx_l0_active_minus1 = pps.num_ref_idx_l0_default_active_minus1;
                if header.slice_type.is_b() {
                    header.num_ref_idx_l1_active_minus1 = pps.num_ref_idx_l1_default_active_minus1;
                }
            }
        }

        if header.field_pic_flag {
            if header.num_ref_idx_l0_active_minus1 > 31 || header.num_ref_idx_l1_active_minus1 > 31
            {
                return Err(anyhow!("Broken Data"));
            }
        } else if header.num_ref_idx_l0_active_minus1 > 15
            || header.num_ref_idx_l1_active_minus1 > 15
        {
            return Err(anyhow!("Broken Data"));
        }

        if let NaluType::SliceExt = nalu.header.type_ {
            return Err(anyhow!("Stream contain unsupported/unimplemented NALs"));
        }

        Parser::parse_ref_pic_list_modifications(&mut r, &mut header)?;

        if (pps.weighted_pred_flag && (header.slice_type.is_p() || header.slice_type.is_sp()))
            || (pps.weighted_bipred_idc == 1 && header.slice_type.is_b())
        {
            Parser::parse_pred_weight_table(&mut r, sps, &mut header)?;
        }

        if nalu.header.ref_idc != 0 {
            Parser::parse_dec_ref_pic_marking(&mut r, &nalu, &mut header)?;
        }

        if pps.entropy_coding_mode_flag && !header.slice_type.is_i() && !header.slice_type.is_si() {
            header.cabac_init_idc = r.read_ue_max(2)?;
        }

        header.slice_qp_delta = r.read_se_bounded(-87, 77)?;

        if header.slice_type.is_sp() || header.slice_type.is_si() {
            if header.slice_type.is_sp() {
                header.sp_for_switch_flag = r.read_bit()?;
            }

            header.slice_qs_delta = r.read_se_bounded(-51, 51)?;
        }

        if pps.deblocking_filter_control_present_flag {
            header.disable_deblocking_filter_idc = r.read_ue_max(2)?;

            if header.disable_deblocking_filter_idc != 1 {
                header.slice_alpha_c0_offset_div2 = r.read_se_bounded(-6, 6)?;
                header.slice_beta_offset_div2 = r.read_se_bounded(-6, 6)?;
            }
        }

        if pps.num_slice_groups_minus1 > 0 {
            return Err(anyhow!("Stream contain unsupported/unimplemented NALs"));
        }

        let epb = r.num_epb();
        header.header_bit_size = (nalu.size - epb) * 8 - r.num_bits_left();

        header.n_emulation_prevention_bytes = epb;

        Ok(Slice { header, nalu })
    }

    pub fn get_sps(&self, sps_id: u8) -> Option<&Sps> {
        self.active_spses.get(&sps_id)
        // &self.active_spses[&sps_id]
    }

    pub fn get_pps(&self, pps_id: u8) -> Option<&Pps> {
        self.active_ppses.get(&pps_id)
    }
}

#[derive(Debug)]
pub struct NaluHeader {
    ref_idc: u8,
    type_: NaluType,
    idr_pic_flag: bool,
    header_bytes: usize,
}

impl NaluHeader {
    /// Get a reference to the nalu header's ref idc.
    pub fn ref_idc(&self) -> u8 {
        self.ref_idc
    }

    /// Get a reference to the nalu header's type.
    pub fn nalu_type(&self) -> &NaluType {
        &self.type_
    }

    /// Get a reference to the nalu header's idr pic flag.
    pub fn idr_pic_flag(&self) -> bool {
        self.idr_pic_flag
    }

    /// Get a reference to the nalu header's header bytes.
    pub fn header_bytes(&self) -> usize {
        self.header_bytes
    }
}

#[derive(Debug)]
pub struct Nalu<T> {
    header: NaluHeader,
    /// The mapping that backs this NALU. Possibly shared with the other NALUs
    /// in the Access Unit.
    data: T,

    size: usize,
    offset: usize,
    sc_offset: usize,
}

impl<T: AsRef<[u8]>> Nalu<T> {
    fn find_start_code(data: &mut Cursor<T>, offset: usize) -> Option<usize> {
        // discard all zeroes until the start code pattern is found
        data.get_ref().as_ref()[offset..]
            .windows(3)
            .position(|window| window == [0x00, 0x00, 0x01])
    }

    fn parse_header(data: &mut Cursor<T>) -> Result<NaluHeader> {
        if !data.has_remaining() {
            return Err(anyhow!("Broken Data"));
        }

        let byte = data.chunk()[0];

        let type_ = NaluType::n(byte & 0x1f).ok_or(anyhow!("Broken Data"))?;

        if let NaluType::SliceExt = type_ {
            return Err(anyhow!("Stream contain unsupported/unimplemented NALs"));
        }

        let ref_idc = (byte & 0x60) >> 5;
        let idr_pic_flag = matches!(type_, NaluType::SliceIdr);

        Ok(NaluHeader {
            ref_idc,
            type_,
            idr_pic_flag,
            header_bytes: 1,
        })
    }

    /// Find the next Annex B encoded NAL unit.
    pub fn next(cursor: &mut Cursor<T>, bitstream: T) -> Result<Option<Nalu<T>>> {
        let pos = usize::try_from(cursor.position())?;

        // Find the start code for this NALU
        let current_nalu_offset = match Nalu::find_start_code(cursor, pos) {
            Some(offset) => offset,
            None => return Err(anyhow!("No NAL found")),
        };

        let mut start_code_offset = pos + current_nalu_offset;

        // If the preceding byte is 00, then we actually have a four byte SC,
        // i.e. 00 00 00 01 Where the first 00 is the "zero_byte()"
        if start_code_offset > 0 && cursor.get_ref().as_ref()[start_code_offset - 1] == 00 {
            start_code_offset -= 1;
        }

        // The NALU offset is its offset + 3 bytes to skip the start code.
        let nalu_offset = pos + current_nalu_offset + 3;

        // Set the bitstream position to the start of the current NALU
        cursor.set_position(u64::try_from(nalu_offset)?);

        let hdr = Nalu::parse_header(cursor)?;

        // Find the start of the subsequent NALU.
        let mut next_nalu_offset = match Nalu::find_start_code(cursor, nalu_offset) {
            Some(offset) => offset,
            None => cursor.chunk().len(), // Whatever data is left must be part of the current NALU
        };

        while next_nalu_offset > 0
            && cursor.get_ref().as_ref()[nalu_offset + next_nalu_offset - 1] == 00
        {
            // Discard trailing_zero_8bits
            next_nalu_offset -= 1;
        }

        let nal_size = match hdr.type_ {
            NaluType::SeqEnd | NaluType::StreamEnd => 1,
            _ => next_nalu_offset,
        };

        Ok(Some(Nalu {
            header: hdr,
            data: bitstream,
            size: nal_size,
            offset: nalu_offset,
            sc_offset: start_code_offset,
        }))
    }

    /// Get a reference to the nalu's header.
    pub fn header(&self) -> &NaluHeader {
        &self.header
    }

    /// Get a reference to the nalu's data.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Get a reference to the nalu's size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a reference to the nalu's offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get a reference to the nalu's sc offset.
    pub fn sc_offset(&self) -> usize {
        self.sc_offset
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Nalu<T> {
    fn as_ref(&self) -> &[u8] {
        let data = self.data.as_ref();
        &data[self.offset..self.offset + self.size]
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::decoders::h264::parser::Level;
    use crate::decoders::h264::parser::Nalu;
    use crate::decoders::h264::parser::NaluType;
    use crate::decoders::h264::parser::Parser;

    const STREAM_TEST_25_FPS: &[u8] = include_bytes!("test_data/test-25fps.h264");
    const STREAM_TEST_25_FPS_NUM_NALUS: usize = 759;

    const STREAM_TEST_25_FPS_SLICE_0: &[u8] =
        include_bytes!("test_data/test-25fps-h264-slice-data-0.bin");
    const STREAM_TEST_25_FPS_SLICE_2: &[u8] =
        include_bytes!("test_data/test-25fps-h264-slice-data-2.bin");
    const STREAM_TEST_25_FPS_SLICE_4: &[u8] =
        include_bytes!("test_data/test-25fps-h264-slice-data-4.bin");

    /// This test is adapted from chromium, available at media/video/h264_parser_unittest.cc
    #[test]
    fn parse_nalus_from_stream_file() {
        let mut cursor = Cursor::new(STREAM_TEST_25_FPS);
        let mut num_nalus = 0;
        while let Ok(Some(_)) = Nalu::next(&mut cursor, STREAM_TEST_25_FPS) {
            num_nalus += 1;
        }

        assert_eq!(num_nalus, STREAM_TEST_25_FPS_NUM_NALUS)
    }

    /// The results were manually extracted from the GStreamer parser using GDB
    /// (gsth264parser.c) in order to compare both implementations using the
    /// following pipeline:
    /// gst-launch-1.0 filesrc location=test-25fps.h264 ! h264parse ! 'video/x-h264,stream-format=byte-stream' ! vah264dec ! fakevideosink
    #[test]
    fn parse_test25fps() {
        let mut cursor = Cursor::new(STREAM_TEST_25_FPS);
        let mut sps_ids = Vec::new();
        let mut pps_ids = Vec::new();
        let mut slices = Vec::new();

        let mut parser = Parser::default();

        while let Ok(Some(nalu)) = Nalu::next(&mut cursor, STREAM_TEST_25_FPS) {
            match nalu.header.type_ {
                NaluType::Slice
                | NaluType::SliceDpa
                | NaluType::SliceDpb
                | NaluType::SliceDpc
                | NaluType::SliceIdr
                | NaluType::SliceExt => {
                    let slice = parser.parse_slice_header(nalu).unwrap();
                    slices.push(slice);
                }
                NaluType::Sps => {
                    let sps = parser.parse_sps(&nalu).unwrap();
                    sps_ids.push(sps.seq_parameter_set_id);
                }
                NaluType::Pps => {
                    let pps = parser.parse_pps(&nalu).unwrap();
                    pps_ids.push(pps.pic_parameter_set_id);
                }
                _ => {
                    continue;
                }
            }
        }

        for sps_id in &sps_ids {
            // four identical SPSes in this stream
            let sps = parser.get_sps(*sps_id).unwrap();

            assert_eq!(sps.seq_parameter_set_id, 0);
            assert_eq!(sps.profile_idc, 77);
            assert_eq!(sps.constraint_set0_flag, false);
            assert_eq!(sps.constraint_set1_flag, true);
            assert_eq!(sps.constraint_set2_flag, false);
            assert_eq!(sps.constraint_set3_flag, false);
            assert_eq!(sps.constraint_set4_flag, false);
            assert_eq!(sps.constraint_set5_flag, false);
            assert_eq!(sps.level_idc, Level::L1_3);
            assert_eq!(sps.chroma_format_idc, 1);
            assert_eq!(sps.separate_colour_plane_flag, false);
            assert_eq!(sps.bit_depth_luma_minus8, 0);
            assert_eq!(sps.bit_depth_chroma_minus8, 0);
            assert_eq!(sps.qpprime_y_zero_transform_bypass_flag, false);
            assert_eq!(sps.seq_scaling_matrix_present_flag, false);

            for outer in &sps.scaling_lists_4x4 {
                for inner in outer {
                    assert_eq!(*inner, 16);
                }
            }

            for outer in &sps.scaling_lists_8x8 {
                for inner in outer {
                    assert_eq!(*inner, 16);
                }
            }

            assert_eq!(sps.log2_max_frame_num_minus4, 1);
            assert_eq!(sps.pic_order_cnt_type, 0);
            assert_eq!(sps.log2_max_pic_order_cnt_lsb_minus4, 3);
            assert_eq!(sps.delta_pic_order_always_zero_flag, false);
            assert_eq!(sps.offset_for_non_ref_pic, 0);
            assert_eq!(sps.offset_for_top_to_bottom_field, 0);
            assert_eq!(sps.num_ref_frames_in_pic_order_cnt_cycle, 0);

            for offset in sps.offset_for_ref_frame {
                assert_eq!(offset, 0);
            }

            assert_eq!(sps.max_num_ref_frames, 2);
            assert_eq!(sps.gaps_in_frame_num_value_allowed_flag, false);
            assert_eq!(sps.pic_width_in_mbs_minus1, 19);
            assert_eq!(sps.pic_height_in_map_units_minus1, 14);
            assert_eq!(sps.frame_mbs_only_flag, true);
            assert_eq!(sps.mb_adaptive_frame_field_flag, false);
            assert_eq!(sps.direct_8x8_inference_flag, false);
            assert_eq!(sps.frame_cropping_flag, false);
            assert_eq!(sps.frame_crop_left_offset, 0);
            assert_eq!(sps.frame_crop_right_offset, 0);
            assert_eq!(sps.frame_crop_top_offset, 0);
            assert_eq!(sps.frame_crop_bottom_offset, 0);
            assert_eq!(sps.chroma_array_type, 1);
            assert_eq!(sps.max_frame_num, 32);
            assert_eq!(sps.width, 320);
            assert_eq!(sps.height, 240);
            assert_eq!(sps.crop_rect_width, 0);
            assert_eq!(sps.crop_rect_height, 0);
            assert_eq!(sps.crop_rect_x, 0);
            assert_eq!(sps.crop_rect_y, 0);
        }

        for pps_id in &pps_ids {
            // four identical SPSes in this stream
            let pps = parser.get_pps(*pps_id).unwrap();
            assert_eq!(pps.pic_parameter_set_id, 0);
            assert_eq!(pps.seq_parameter_set_id, 0);
            assert_eq!(pps.bottom_field_pic_order_in_frame_present_flag, true);
            assert_eq!(pps.num_slice_groups_minus1, 0);
            assert_eq!(pps.num_ref_idx_l0_default_active_minus1, 0);
            assert_eq!(pps.num_ref_idx_l1_default_active_minus1, 0);
            assert_eq!(pps.weighted_pred_flag, false);
            assert_eq!(pps.weighted_bipred_idc, 0);
            assert_eq!(pps.pic_init_qp_minus26, 2);
            assert_eq!(pps.pic_init_qs_minus26, 0);
            assert_eq!(pps.chroma_qp_index_offset, 0);
            assert_eq!(pps.deblocking_filter_control_present_flag, false);
            assert_eq!(pps.constrained_intra_pred_flag, false);
            assert_eq!(pps.redundant_pic_cnt_present_flag, false);
            assert_eq!(pps.transform_8x8_mode_flag, false);

            for outer in &pps.scaling_lists_4x4 {
                for inner in outer {
                    assert_eq!(*inner, 16);
                }
            }

            for outer in &pps.scaling_lists_8x8 {
                for inner in outer {
                    assert_eq!(*inner, 16);
                }
            }

            assert_eq!(pps.second_chroma_qp_index_offset, 0);
            assert_eq!(pps.pic_scaling_matrix_present_flag, false);
        }

        // test an I slice
        let hdr = &slices[0].header;
        let nalu = &slices[0].nalu;
        assert_eq!(nalu.as_ref(), STREAM_TEST_25_FPS_SLICE_0);

        assert_eq!(hdr.first_mb_in_slice, 0);
        assert_eq!(hdr.slice_type.is_i(), true);
        assert_eq!(hdr.colour_plane_id, 0);
        assert_eq!(hdr.frame_num, 0);
        assert_eq!(hdr.field_pic_flag, false);
        assert_eq!(hdr.bottom_field_flag, false);
        assert_eq!(hdr.idr_pic_id, 0);
        assert_eq!(hdr.pic_order_cnt_lsb, 0);
        assert_eq!(hdr.delta_pic_order_cnt_bottom, 0);
        assert_eq!(hdr.delta_pic_order_cnt[0], 0);
        assert_eq!(hdr.delta_pic_order_cnt[1], 0);
        assert_eq!(hdr.redundant_pic_cnt, 0);
        assert_eq!(hdr.direct_spatial_mv_pred_flag, false);
        assert_eq!(hdr.num_ref_idx_l0_active_minus1, 0);
        assert_eq!(hdr.num_ref_idx_l1_active_minus1, 0);
        assert_eq!(hdr.ref_pic_list_modification_flag_l0, false);

        assert_eq!(hdr.ref_pic_list_modification_l0.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l0 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        assert_eq!(hdr.ref_pic_list_modification_flag_l1, false);
        assert_eq!(hdr.ref_pic_list_modification_l1.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l1 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        // Safe because this type does not have any references
        assert_eq!(hdr.pred_weight_table, unsafe { std::mem::zeroed() });

        assert_eq!(hdr.dec_ref_pic_marking, Default::default());

        assert_eq!(hdr.cabac_init_idc, 0);
        assert_eq!(hdr.slice_qp_delta, 12);
        assert_eq!(hdr.slice_qs_delta, 0);
        assert_eq!(hdr.disable_deblocking_filter_idc, 0);
        assert_eq!(hdr.slice_alpha_c0_offset_div2, 0);
        assert_eq!(hdr.slice_beta_offset_div2, 0);
        assert_eq!(hdr.max_pic_num, 32);
        assert_eq!(hdr.header_bit_size, 38);
        assert_eq!(hdr.num_ref_idx_active_override_flag, false);

        // test a P slice
        let hdr = &slices[2].header;
        let nalu = &slices[2].nalu;
        assert_eq!(nalu.as_ref(), STREAM_TEST_25_FPS_SLICE_2);

        assert_eq!(hdr.first_mb_in_slice, 0);
        assert_eq!(hdr.slice_type.is_p(), true);
        assert_eq!(hdr.colour_plane_id, 0);
        assert_eq!(hdr.frame_num, 1);
        assert_eq!(hdr.field_pic_flag, false);
        assert_eq!(hdr.bottom_field_flag, false);
        assert_eq!(hdr.idr_pic_id, 0);
        assert_eq!(hdr.pic_order_cnt_lsb, 4);
        assert_eq!(hdr.delta_pic_order_cnt_bottom, 0);
        assert_eq!(hdr.delta_pic_order_cnt[0], 0);
        assert_eq!(hdr.delta_pic_order_cnt[1], 0);
        assert_eq!(hdr.redundant_pic_cnt, 0);
        assert_eq!(hdr.direct_spatial_mv_pred_flag, false);
        assert_eq!(hdr.num_ref_idx_l0_active_minus1, 0);
        assert_eq!(hdr.num_ref_idx_l1_active_minus1, 0);
        assert_eq!(hdr.ref_pic_list_modification_flag_l0, false);

        assert_eq!(hdr.ref_pic_list_modification_l0.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l0 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        assert_eq!(hdr.ref_pic_list_modification_flag_l1, false);
        assert_eq!(hdr.ref_pic_list_modification_l1.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l1 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        // Safe because this type does not have any references
        assert_eq!(hdr.pred_weight_table, unsafe { std::mem::zeroed() });

        assert_eq!(hdr.dec_ref_pic_marking, Default::default());

        assert_eq!(hdr.cabac_init_idc, 0);
        assert_eq!(hdr.slice_qp_delta, 0);
        assert_eq!(hdr.slice_qs_delta, 0);
        assert_eq!(hdr.disable_deblocking_filter_idc, 0);
        assert_eq!(hdr.slice_alpha_c0_offset_div2, 0);
        assert_eq!(hdr.slice_beta_offset_div2, 0);
        assert_eq!(hdr.max_pic_num, 32);
        assert_eq!(hdr.header_bit_size, 28);
        assert_eq!(hdr.num_ref_idx_active_override_flag, false);

        // test a B slice
        let hdr = &slices[4].header;
        let nalu = &slices[4].nalu;
        assert_eq!(nalu.as_ref(), STREAM_TEST_25_FPS_SLICE_4);

        assert_eq!(hdr.first_mb_in_slice, 0);
        assert_eq!(hdr.slice_type.is_b(), true);
        assert_eq!(hdr.colour_plane_id, 0);
        assert_eq!(hdr.frame_num, 2);
        assert_eq!(hdr.field_pic_flag, false);
        assert_eq!(hdr.bottom_field_flag, false);
        assert_eq!(hdr.idr_pic_id, 0);
        assert_eq!(hdr.pic_order_cnt_lsb, 2);
        assert_eq!(hdr.delta_pic_order_cnt_bottom, 0);
        assert_eq!(hdr.delta_pic_order_cnt[0], 0);
        assert_eq!(hdr.delta_pic_order_cnt[1], 0);
        assert_eq!(hdr.redundant_pic_cnt, 0);
        assert_eq!(hdr.direct_spatial_mv_pred_flag, true);
        assert_eq!(hdr.num_ref_idx_l0_active_minus1, 0);
        assert_eq!(hdr.num_ref_idx_l1_active_minus1, 0);
        assert_eq!(hdr.ref_pic_list_modification_flag_l0, false);

        assert_eq!(hdr.ref_pic_list_modification_l0.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l0 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        assert_eq!(hdr.ref_pic_list_modification_flag_l1, false);
        assert_eq!(hdr.ref_pic_list_modification_l1.len(), 0);

        for rplm in &hdr.ref_pic_list_modification_l1 {
            assert_eq!(rplm.modification_of_pic_nums_idc, 0);
            assert_eq!(rplm.abs_diff_pic_num_minus1, 0);
            assert_eq!(rplm.long_term_pic_num, 0);
            assert_eq!(rplm.abs_diff_view_idx_minus1, 0);
        }

        // Safe because this type does not have any references
        assert_eq!(hdr.pred_weight_table, unsafe { std::mem::zeroed() });

        assert_eq!(hdr.dec_ref_pic_marking, Default::default());

        assert_eq!(hdr.cabac_init_idc, 0);
        assert_eq!(hdr.slice_qp_delta, 16);
        assert_eq!(hdr.slice_qs_delta, 0);
        assert_eq!(hdr.disable_deblocking_filter_idc, 0);
        assert_eq!(hdr.slice_alpha_c0_offset_div2, 0);
        assert_eq!(hdr.slice_beta_offset_div2, 0);
        assert_eq!(hdr.max_pic_num, 32);
        assert_eq!(hdr.header_bit_size, 41);
        assert_eq!(hdr.num_ref_idx_active_override_flag, false);
    }
}

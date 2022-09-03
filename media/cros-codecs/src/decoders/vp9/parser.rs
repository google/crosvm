// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use bitreader::BitReader;
use enumn::N;

pub const REFS_PER_FRAME: usize = 3;

pub const MAX_REF_LF_DELTAS: usize = 4;
pub const MAX_MODE_LF_DELTAS: usize = 2;

pub const INTRA_FRAME: usize = 0;
pub const LAST_FRAME: usize = 1;
pub const GOLDEN_FRAME: usize = 2;
pub const ALTREF_FRAME: usize = 3;
pub const MAX_REF_FRAMES: usize = 4;

pub const MAX_SEGMENTS: usize = 8;
pub const SEG_TREE_PROBS: usize = MAX_SEGMENTS - 1;
pub const PREDICTION_PROBS: usize = 3;

pub const SEG_LVL_ALT_L: usize = 1;
pub const SEG_LVL_REF_FRAME: usize = 2;
pub const SEG_LVL_SKIP: usize = 3;
pub const SEG_LVL_MAX: usize = 4;

pub const MAX_LOOP_FILTER: u32 = 63;

pub const REF_FRAMES_LOG2: usize = 3;
pub const REF_FRAMES: usize = 1 << REF_FRAMES_LOG2;

pub const SUPERFRAME_MARKER: u32 = 0x06;
pub const MAX_FRAMES_IN_SUPERFRAME: usize = 8;

pub const FRAME_MARKER: u32 = 0x02;
pub const SYNC_CODE: u32 = 0x498342;

pub const MIN_TILE_WIDTH_B64: u32 = 4;
pub const MAX_TILE_WIDTH_B64: u32 = 64;

/// The number of pictures in the DPB
pub const NUM_REF_FRAMES: usize = 8;

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum InterpolationFilter {
    EightTap = 0,
    EightTapSmooth = 1,
    EightTapSharp = 2,
    Bilinear = 3,
    Switchable = 4,
}

impl Default for InterpolationFilter {
    fn default() -> Self {
        InterpolationFilter::EightTap
    }
}

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum ReferenceFrameType {
    Intra = 0,
    Last = 1,
    Golden = 2,
    AltRef = 3,
}

#[derive(Copy, Clone, Debug, PartialEq, N)]

pub enum FrameType {
    KeyFrame = 0,
    InterFrame = 1,
}

impl Default for FrameType {
    fn default() -> Self {
        FrameType::KeyFrame
    }
}

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum Profile {
    Profile0 = 0,
    Profile1 = 1,
    Profile2 = 2,
    Profile3 = 3,
}

impl Default for Profile {
    fn default() -> Self {
        Profile::Profile0
    }
}

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum BitDepth {
    Depth8 = 8,
    Depth10 = 10,
    Depth12 = 12,
}

impl Default for BitDepth {
    fn default() -> Self {
        BitDepth::Depth8
    }
}

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum ColorSpace {
    Unknown = 0,
    Bt601 = 1,
    Bt709 = 2,
    Smpte170 = 3,
    Smpte240 = 4,
    Bt2020 = 5,
    Reserved2 = 6,
    CsSrgb = 7,
}

impl Default for ColorSpace {
    fn default() -> Self {
        ColorSpace::Unknown
    }
}

#[derive(Copy, Clone, Debug, PartialEq, N)]
pub enum ColorRange {
    StudioSwing = 0,
    FullSwing = 1,
}

impl Default for ColorRange {
    fn default() -> Self {
        ColorRange::StudioSwing
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LoopFilterParams {
    /// Indicates the loop filter strength.
    level: u8,
    /// Indicates the sharpness level. The loop filter level and loop
    /// filter_sharpness together determine when a block edge is filtered, and
    /// by how much the filtering can change the sample values.
    sharpness: u8,
    /// If set, means that the filter level depends on the mode and reference
    /// frame used to predict a block. If unset, means that the filter level
    /// does not depend on the mode and reference frame.
    delta_enabled: bool,
    /// If set, means that the bitstream contains additional syntax elements
    /// that specify which mode and reference frame deltas are to be updated. If
    /// unset, means that these syntax elements are not present.
    delta_update: bool,
    /// If set, means that the bitstream contains additional syntax elements
    /// that specify which mode and reference frame deltas are to be updated. If
    /// unset, means that these syntax elements are not present.
    update_ref_delta: [bool; MAX_REF_LF_DELTAS],
    /// Contains the adjustment needed for the filter level based on the chosen
    /// reference frame. If this syntax element is not present in the bitstream,
    /// it maintains its previous value.
    ref_deltas: [i8; MAX_REF_LF_DELTAS],
    ///  If set, means that the bitstream contains the syntax element
    ///  loop_filter_mode_deltas. If unset, means that the bitstream does not
    ///  contain this syntax element.
    update_mode_delta: [bool; MAX_MODE_LF_DELTAS],
    /// Contains the adjustment needed for the filter level based on the chosen
    /// mode. If this syntax element is not present in the bitstream, it
    /// maintains its previous value.
    mode_deltas: [i8; MAX_MODE_LF_DELTAS],
}

impl LoopFilterParams {
    /// Get a reference to the loop filter params's level.
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Get a reference to the loop filter params's sharpness.
    pub fn sharpness(&self) -> u8 {
        self.sharpness
    }

    /// Get a reference to the loop filter params's delta enabled.
    pub fn delta_enabled(&self) -> bool {
        self.delta_enabled
    }

    /// Get a reference to the loop filter params's delta update.
    pub fn delta_update(&self) -> bool {
        self.delta_update
    }

    /// Get a reference to the loop filter params's update ref delta.
    pub fn update_ref_delta(&self) -> [bool; MAX_REF_LF_DELTAS] {
        self.update_ref_delta
    }

    /// Get a reference to the loop filter params's ref deltas.
    pub fn ref_deltas(&self) -> [i8; MAX_REF_LF_DELTAS] {
        self.ref_deltas
    }

    /// Get a reference to the loop filter params's update mode delta.
    pub fn update_mode_delta(&self) -> [bool; MAX_MODE_LF_DELTAS] {
        self.update_mode_delta
    }

    /// Get a reference to the loop filter params's mode deltas.
    pub fn mode_deltas(&self) -> [i8; MAX_MODE_LF_DELTAS] {
        self.mode_deltas
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuantizationParams {
    /// Indicates the base frame qindex. This is used for Y AC coefficients and
    /// as the base value for the other quantizers.
    base_q_idx: u8,
    /// Indicates the Y DC quantizer relative to base_q_idx.
    delta_q_y_dc: i8,
    /// Indicates the UV DC quantizer relative to base_q_idx.
    delta_q_uv_dc: i8,
    /// Indicates the UV AC quantizer relative to base_q_idx.
    delta_q_uv_ac: i8,
}

impl QuantizationParams {
    /// Get a reference to the quantization params's base q idx.
    pub fn base_q_idx(&self) -> u8 {
        self.base_q_idx
    }

    /// Get a reference to the quantization params's delta q y dc.
    pub fn delta_q_y_dc(&self) -> i8 {
        self.delta_q_y_dc
    }

    /// Get a reference to the quantization params's delta q uv dc.
    pub fn delta_q_uv_dc(&self) -> i8 {
        self.delta_q_uv_dc
    }

    /// Get a reference to the quantization params's delta q uv ac.
    pub fn delta_q_uv_ac(&self) -> i8 {
        self.delta_q_uv_ac
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SegmentationParams {
    ///  If set, indicates that this frame makes use of the segmentation tool.
    ///  If unset, indicates that the frame does not use segmentation.
    enabled: bool,
    /// If set, indicates that the segmentation map should be updated during
    /// the decoding of this frame. If unset, means that the segmentation map
    /// from the previous frame is used.
    update_map: bool,
    /// Specify the probability values to be used when decoding segment_id.
    tree_probs: [u8; SEG_TREE_PROBS],
    /// Specify the probability values to be used when decoding seg_id_predicted.
    pred_probs: [u8; PREDICTION_PROBS],
    /// If set, indicates that the updates to the segmentation map are coded
    /// relative to the existing segmentation map. If unset,
    /// indicates that the new segmentation map is coded without
    /// reference to the existing segmentation map.
    temporal_update: bool,
    /// If set, indicates that new parameters are about to be specified for each
    /// segment. If unset, indicates that the segmentation parameters should
    /// keep their existing values.
    update_data: bool,
    /// If unset, indicates that the segmentation parameters represent
    /// adjustments relative to the standard values. If set, indicates that the
    /// segmentation parameters represent the actual values to be used.
    abs_or_delta_update: bool,
    /// If unset, indicates that the corresponding feature is unused and has
    /// value equal to 0. if set, indicates that the feature value is coded in
    /// the bitstream.
    feature_enabled: [[bool; SEG_LVL_MAX]; MAX_SEGMENTS],
    /// Specifies the magnitude of the feature data for a segment feature.
    feature_data: [[i16; SEG_LVL_MAX]; MAX_SEGMENTS],
}

impl SegmentationParams {
    /// Get a reference to the segmentation params's enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Get a reference to the segmentation params's update map.
    pub fn update_map(&self) -> bool {
        self.update_map
    }

    /// Get a reference to the segmentation params's tree probs.
    pub fn tree_probs(&self) -> [u8; SEG_TREE_PROBS] {
        self.tree_probs
    }

    /// Get a reference to the segmentation params's pred probs.
    pub fn pred_probs(&self) -> [u8; PREDICTION_PROBS] {
        self.pred_probs
    }

    /// Get a reference to the segmentation params's temporal update.
    pub fn temporal_update(&self) -> bool {
        self.temporal_update
    }

    /// Get a reference to the segmentation params's update data.
    pub fn update_data(&self) -> bool {
        self.update_data
    }

    /// Get a reference to the segmentation params's abs or delta update.
    pub fn abs_or_delta_update(&self) -> bool {
        self.abs_or_delta_update
    }

    /// Get a reference to the segmentation params's feature enabled.
    pub fn feature_enabled(&self) -> [[bool; SEG_LVL_MAX]; MAX_SEGMENTS] {
        self.feature_enabled
    }

    /// Get a reference to the segmentation params's feature data.
    pub fn feature_data(&self) -> [[i16; SEG_LVL_MAX]; MAX_SEGMENTS] {
        self.feature_data
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct FrameSize {
    width: u32,
    height: u32,
}

pub struct Frame<T> {
    /// The abstraction for the raw memory for this frame.
    pub bitstream: T,
    /// The frame header.
    pub header: Header,
    /// The offset into T
    offset: usize,
    /// The size of the data in T
    size: usize,
}
impl<T: AsRef<[u8]>> Frame<T> {
    pub fn new(bitstream: T, header: Header, offset: usize, size: usize) -> Self {
        Self {
            bitstream,
            header,
            offset,
            size,
        }
    }

    /// Get a reference to the frame's offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get a reference to the frame's size.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        let data = self.bitstream.as_ref();
        &data[self.offset..self.offset + self.size]
    }
}

/// A VP9 frame header.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Header {
    /// A subset of syntax, semantics and algorithms defined in a part.
    profile: Profile,
    /// The bit depth of the frame.
    bit_depth: BitDepth,
    /// Specifies the chroma subsampling format.
    subsampling_x: bool,
    /// Specifies the chroma subsampling format.
    subsampling_y: bool,
    /// Specifies the color space of the stream.
    color_space: ColorSpace,
    /// Specifies the black level and range of the luma and chroma signals as
    /// specified in Rec. ITU-R BT.709-6 and Rec. ITU-R BT.2020-2
    color_range: ColorRange,
    /// Indicates the frame indexed by frame_to_show_map_idx is to be displayed.
    /// If unset, indicates that further processing is required.
    show_existing_frame: bool,
    /// Specifies the frame to be displayed. It is only available if
    /// show_existing_frame is set.
    frame_to_show_map_idx: u8,
    /// Indicates whether a frame is a key frame.
    frame_type: FrameType,
    /// Whether this frame should be displayed.
    show_frame: bool,
    /// Whether error resilient mode is enabled.
    error_resilient_mode: bool,
    /// The width of the frame in pixels.
    width: u32,
    /// The height of the frame in pixels.
    height: u32,
    /// If unset, means that the render width and height are inferred from the
    /// frame width and height. If set, means that the render width and height
    /// are explicitly coded in the bitstream.
    render_and_frame_size_different: bool,
    /// The render width of the frame in pixels.
    render_width: u32,
    /// The render height of the frame in pixels.
    render_height: u32,
    /// If set, indicates that this frame is an intra-only frame. If unset,
    /// indicates that this frame is a inter frame.
    intra_only: bool,
    /// Specifies whether the frame context should be reset to default values.
    reset_frame_context: u8,
    /// Contains a bitmask that specifies which reference frame slots will be
    /// updated with the current frame after it is decoded.
    refresh_frame_flags: u8,
    /// Specifies which reference frames are used by inter frames. It is a
    /// requirement of bitstream conformance that the selected reference frames
    /// match the current frame in bit depth, profile, chroma subsampling, and
    /// color space.
    ref_frame_idx: [u8; REFS_PER_FRAME],
    /// Specifies the intended direction of the motion vector in time for each
    /// reference frame. A sign bias equal to 0 indicates that the reference
    /// frame is a backwards reference; a sign bias equal to 1 indicates that
    /// the reference frame is a forwards reference
    ref_frame_sign_bias: [u8; 4],
    /// If unset, specifies that motion vectors are specified to quarter pel
    /// precision. If set, specifies that motion vectors are specified to eighth
    /// pel precision.
    allow_high_precision_mv: bool,
    /// The interpolation filter parameters.
    interpolation_filter: InterpolationFilter,
    /// If set, indicates that the probabilities computed for this frame (after
    /// adapting to the observed frequencies if adaption is enabled) should be
    /// stored for reference by future frames. If unset, indicates that the
    /// probabilities should be discarded at the end of the frame.
    refresh_frame_context: bool,
    /// Whether parallel decoding mode is enabled.
    frame_parallel_decoding_mode: bool,
    /// Indicates the frame context to use.
    frame_context_idx: u8,
    /// The loop filter parameters
    lf: LoopFilterParams,
    /// The quantization parameters.
    quant: QuantizationParams,
    /// The segmentation parameters
    seg: SegmentationParams,
    /// Specifies the base 2 logarithm of the width of each tile (where the
    /// width is measured in units of 8x8 blocks). It is a requirement of
    /// bitstream conformance that tile_cols_log2 is less than or equal to 6.
    tile_cols_log2: u8,
    /// Specifies the base 2 logarithm of the height of each tile (where the
    /// height is measured in units of 8x8 blocks).
    tile_rows_log2: u8,
    /// Computed from the syntax elements. If set, indicates that the frame is
    /// coded using a special 4x4 transform designed for encoding frames that
    /// are bit-identical with the original frames.
    lossless: bool,
    /// Indicates the size of the compressed header in bytes.
    header_size_in_bytes: u16,
    /// Indicates the size of the uncompressed header in bytes.
    uncompressed_header_size_in_bytes: u16,
}

impl Header {
    /// Get a reference to the header's profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Get a reference to the header's bit depth.
    pub fn bit_depth(&self) -> BitDepth {
        self.bit_depth
    }

    /// Get a reference to the header's subsampling x.
    pub fn subsampling_x(&self) -> bool {
        self.subsampling_x
    }

    /// Get a reference to the header's subsampling y.
    pub fn subsampling_y(&self) -> bool {
        self.subsampling_y
    }

    /// Get a reference to the header's color space.
    pub fn color_space(&self) -> ColorSpace {
        self.color_space
    }

    /// Get a reference to the header's color range.
    pub fn color_range(&self) -> ColorRange {
        self.color_range
    }

    /// Get a reference to the header's show existing frame.
    pub fn show_existing_frame(&self) -> bool {
        self.show_existing_frame
    }

    /// Get a reference to the header's frame to show map idx.
    pub fn frame_to_show_map_idx(&self) -> u8 {
        self.frame_to_show_map_idx
    }

    /// Get a reference to the header's frame type.
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Get a reference to the header's show frame.
    pub fn show_frame(&self) -> bool {
        self.show_frame
    }

    /// Get a reference to the header's error resilient mode.
    pub fn error_resilient_mode(&self) -> bool {
        self.error_resilient_mode
    }

    /// Get a reference to the header's width.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get a reference to the header's height.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get a reference to the header's render and frame size different.
    pub fn render_and_frame_size_different(&self) -> bool {
        self.render_and_frame_size_different
    }

    /// Get a reference to the header's render width.
    pub fn render_width(&self) -> u32 {
        self.render_width
    }

    /// Get a reference to the header's render height.
    pub fn render_height(&self) -> u32 {
        self.render_height
    }

    /// Get a reference to the header's intra only.
    pub fn intra_only(&self) -> bool {
        self.intra_only
    }

    /// Get a reference to the header's reset frame context.
    pub fn reset_frame_context(&self) -> u8 {
        self.reset_frame_context
    }

    /// Get a reference to the header's refresh frame flags.
    pub fn refresh_frame_flags(&self) -> u8 {
        self.refresh_frame_flags
    }

    /// Get a reference to the header's ref frame idx.
    pub fn ref_frame_idx(&self) -> [u8; REFS_PER_FRAME] {
        self.ref_frame_idx
    }

    /// Get a reference to the header's ref frame sign bias.
    pub fn ref_frame_sign_bias(&self) -> [u8; 4] {
        self.ref_frame_sign_bias
    }

    /// Get a reference to the header's allow high precision mv.
    pub fn allow_high_precision_mv(&self) -> bool {
        self.allow_high_precision_mv
    }

    /// Get a reference to the header's interpolation filter.
    pub fn interpolation_filter(&self) -> InterpolationFilter {
        self.interpolation_filter
    }

    /// Get a reference to the header's refresh frame context.
    pub fn refresh_frame_context(&self) -> bool {
        self.refresh_frame_context
    }

    /// Get a reference to the header's frame parallel decoding mode.
    pub fn frame_parallel_decoding_mode(&self) -> bool {
        self.frame_parallel_decoding_mode
    }

    /// Get a reference to the header's frame context idx.
    pub fn frame_context_idx(&self) -> u8 {
        self.frame_context_idx
    }

    /// Get a reference to the header's lf.
    pub fn lf(&self) -> &LoopFilterParams {
        &self.lf
    }

    /// Get a reference to the header's quant.
    pub fn quant(&self) -> &QuantizationParams {
        &self.quant
    }

    /// Get a reference to the header's seg.
    pub fn seg(&self) -> &SegmentationParams {
        &self.seg
    }

    /// Get a reference to the header's tile cols log2.
    pub fn tile_cols_log2(&self) -> u8 {
        self.tile_cols_log2
    }

    /// Get a reference to the header's tile rows log2.
    pub fn tile_rows_log2(&self) -> u8 {
        self.tile_rows_log2
    }

    /// Get a reference to the header's lossless.
    pub fn lossless(&self) -> bool {
        self.lossless
    }

    /// Get a reference to the header's header size in bytes.
    pub fn header_size_in_bytes(&self) -> u16 {
        self.header_size_in_bytes
    }

    /// Get a reference to the header's uncompressed header size in bytes.
    pub fn uncompressed_header_size_in_bytes(&self) -> u16 {
        self.uncompressed_header_size_in_bytes
    }
}

/// The VP9 superframe header as per Annex B, B.2.1, B.2.2
pub struct SuperframeHeader {
    /// Indicates the number of frames within this superframe. NOTE - It is
    /// legal for a superframe to contain just a single frame and have NumFrames
    /// equal to 1.
    frames_in_superframe: u32,
    /// Specifies the size in bytes of frame number i (zero indexed) within this
    /// superframe.
    frame_sizes: Vec<usize>,
}
/// A VP9 bitstream parser.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Parser {
    bit_depth: BitDepth,
    subsampling_x: bool,
    subsampling_y: bool,
    color_space: ColorSpace,
    color_range: ColorRange,

    mi_cols: u32,
    mi_rows: u32,
    sb64_cols: u32,
    sb64_rows: u32,

    lf: LoopFilterParams,
    seg: SegmentationParams,

    reference_frame_sz: [FrameSize; REF_FRAMES],
}

impl Parser {
    fn parse_superframe_hdr(&mut self, resource: impl AsRef<[u8]>) -> Result<SuperframeHeader> {
        let bitstream = resource.as_ref();

        // Skip to the end of the chunk.
        let mut reader = BitReader::new(&bitstream[bitstream.len() - 1..]);

        // Try reading a superframe marker.
        let marker = reader.read_u32(3)?;

        if marker != SUPERFRAME_MARKER {
            // Not a superframe
            return Ok(SuperframeHeader {
                frames_in_superframe: 1,
                frame_sizes: vec![bitstream.len()],
            });
        }

        let bytes_per_framesize = reader.read_u32(2)? + 1;
        let frames_in_superframe = reader.read_u32(3)? + 1;

        if frames_in_superframe > MAX_FRAMES_IN_SUPERFRAME as u32 {
            return Err(anyhow!(
                "Broken stream: too many frames in superframe, expected a maximum of {:?}, found {:?}",
                MAX_FRAMES_IN_SUPERFRAME,
                frames_in_superframe
            ));
        }

        let sz_index = 2 + frames_in_superframe * bytes_per_framesize;

        let data = resource.as_ref();
        let index_offset = data.len() - sz_index as usize;
        let first_byte = data[index_offset];
        let last_byte = *data.last().unwrap();

        if first_byte != last_byte {
            // Also not a superframe, we must pass both tests as per the specification.
            return Ok(SuperframeHeader {
                frames_in_superframe: 1,
                frame_sizes: vec![bitstream.len()],
            });
        }

        let mut frame_sizes = vec![];
        let mut reader = BitReader::new(&bitstream[index_offset..]);

        // Skip the superframe header.
        let _ = reader.read_u32(8)?;

        for _ in 0..frames_in_superframe {
            let mut frame_size = 0;

            for j in 0..bytes_per_framesize {
                frame_size |= reader.read_u32(8)? << (j * 8);
            }

            frame_sizes.push(frame_size as usize);
        }

        Ok(SuperframeHeader {
            frames_in_superframe,
            frame_sizes,
        })
    }

    fn read_signed_8(r: &mut BitReader, nbits: u8) -> Result<i8> {
        let value = r.read_u8(nbits)?;

        let negative = r.read_bool()?;

        if negative {
            Ok(-(value as i8))
        } else {
            Ok(value as i8)
        }
    }

    fn parse_frame_marker(r: &mut BitReader) -> Result<()> {
        let marker = r.read_u32(2)?;

        if marker != FRAME_MARKER {
            return Err(anyhow!(
                "Broken stream: expected frame marker, found {:?}",
                marker
            ));
        }

        Ok(())
    }

    fn parse_profile(r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        let low = r.read_u32(1)?;
        let high = r.read_u32(1)?;

        let profile = (high << 1) | low;

        if profile == 3 {
            // Skip the reserved bit
            let _ = r.read_bool()?;
        }

        hdr.profile = Profile::n(profile)
            .with_context(|| format!("Broken stream: invalid profile {:?}", profile))?;

        Ok(())
    }

    fn parse_frame_sync_code(r: &mut BitReader) -> Result<()> {
        let sync_code = r.read_u32(24)?;

        if sync_code != SYNC_CODE {
            return Err(anyhow!(
                "Broken stream: expected sync code == {:?}, found {:?}",
                SYNC_CODE,
                sync_code
            ));
        }

        Ok(())
    }

    fn parse_color_config(&mut self, r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        if matches!(hdr.profile, Profile::Profile2 | Profile::Profile3) {
            let ten_or_twelve_bit = r.read_bool()?;
            if ten_or_twelve_bit {
                hdr.bit_depth = BitDepth::Depth12;
            } else {
                hdr.bit_depth = BitDepth::Depth10
            }
        } else {
            hdr.bit_depth = BitDepth::Depth8;
        }

        let color_space = r.read_u32(3)?;
        hdr.color_space = ColorSpace::n(color_space)
            .with_context(|| format!("Broken stream: invalid color space: {:?}", color_space))?;

        if !matches!(hdr.color_space, ColorSpace::CsSrgb) {
            let color_range = r.read_u32(1)?;

            hdr.color_range = ColorRange::n(color_range).with_context(|| {
                format!("Broken stream: invalid color range: {:?}", color_range)
            })?;

            if matches!(hdr.profile, Profile::Profile1 | Profile::Profile3) {
                hdr.subsampling_x = r.read_bool()?;
                hdr.subsampling_y = r.read_bool()?;

                // Skip the reserved bit
                let _ = r.read_bool()?;
            } else {
                hdr.subsampling_x = true;
                hdr.subsampling_y = true;
            }
        } else {
            hdr.color_range = ColorRange::FullSwing;
            if matches!(hdr.profile, Profile::Profile1 | Profile::Profile3) {
                hdr.subsampling_x = false;
                hdr.subsampling_y = false;

                // Skip the reserved bit
                let _ = r.read_bool()?;
            }
        }

        self.bit_depth = hdr.bit_depth;
        self.color_space = hdr.color_space;
        self.subsampling_x = hdr.subsampling_x;
        self.subsampling_y = hdr.subsampling_y;
        self.color_range = hdr.color_range;

        Ok(())
    }

    fn compute_image_size(&mut self, width: u32, height: u32) {
        self.mi_cols = (width + 7) >> 3;
        self.mi_rows = (height + 7) >> 3;
        self.sb64_cols = (self.mi_cols + 7) >> 3;
        self.sb64_rows = (self.mi_rows + 7) >> 3;
    }

    fn parse_frame_size(&mut self, r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        hdr.width = r.read_u32(16)? + 1;
        hdr.height = r.read_u32(16)? + 1;
        self.compute_image_size(hdr.width, hdr.height);
        Ok(())
    }

    fn parse_render_size(&mut self, r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        hdr.render_and_frame_size_different = r.read_bool()?;
        if hdr.render_and_frame_size_different {
            hdr.render_width = r.read_u32(16)? + 1;
            hdr.render_height = r.read_u32(16)? + 1;
        } else {
            hdr.render_width = hdr.width;
            hdr.render_height = hdr.height;
        }

        Ok(())
    }

    fn parse_frame_size_with_refs(&mut self, r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        let mut found_ref = false;

        for i in 0..REFS_PER_FRAME {
            found_ref = r.read_bool()?;

            if found_ref {
                let idx = hdr.ref_frame_idx[i] as usize;
                hdr.width = self.reference_frame_sz[idx].width;
                hdr.height = self.reference_frame_sz[idx].height;
                break;
            }
        }

        if !found_ref {
            self.parse_frame_size(r, hdr)?;
        } else {
            self.compute_image_size(hdr.width, hdr.height)
        }

        self.parse_render_size(r, hdr)
    }

    fn read_interpolation_filter(r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        const LITERAL_TO_TYPE: [InterpolationFilter; 4] = [
            InterpolationFilter::EightTapSmooth,
            InterpolationFilter::EightTap,
            InterpolationFilter::EightTapSharp,
            InterpolationFilter::Bilinear,
        ];

        let is_filter_switchable = r.read_bool()?;

        if is_filter_switchable {
            hdr.interpolation_filter = InterpolationFilter::Switchable;
        } else {
            let raw_interpolation_filter = r.read_u32(2)?;
            hdr.interpolation_filter = LITERAL_TO_TYPE[raw_interpolation_filter as usize];
        }

        Ok(())
    }

    fn setup_past_independence(&mut self, hdr: &mut Header) {
        self.seg.feature_enabled = Default::default();
        self.seg.feature_data = Default::default();
        self.seg.abs_or_delta_update = false;

        self.lf.delta_enabled = true;
        self.lf.ref_deltas[ReferenceFrameType::Intra as usize] = 1;
        self.lf.ref_deltas[ReferenceFrameType::Last as usize] = 0;
        self.lf.ref_deltas[ReferenceFrameType::Golden as usize] = -1;
        self.lf.ref_deltas[ReferenceFrameType::AltRef as usize] = -1;

        self.lf.mode_deltas = Default::default();
        hdr.ref_frame_sign_bias = Default::default();
    }

    fn parse_loop_filter_params(r: &mut BitReader, lf: &mut LoopFilterParams) -> Result<()> {
        lf.level = r.read_u8(6)?;
        lf.sharpness = r.read_u8(3)?;
        lf.delta_enabled = r.read_bool()?;

        if lf.delta_enabled {
            lf.delta_update = r.read_bool()?;
            if lf.delta_update {
                for i in 0..MAX_REF_LF_DELTAS {
                    lf.update_ref_delta[i] = r.read_bool()?;
                    if lf.update_ref_delta[i] {
                        lf.ref_deltas[i] = Self::read_signed_8(r, 6)?;
                    }
                }

                for i in 0..MAX_MODE_LF_DELTAS {
                    lf.update_mode_delta[i] = r.read_bool()?;
                    if lf.update_mode_delta[i] {
                        lf.mode_deltas[i] = Self::read_signed_8(r, 6)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn read_delta_q(r: &mut BitReader, value: &mut i8) -> Result<()> {
        let delta_coded = r.read_bool()?;

        if delta_coded {
            *value = Self::read_signed_8(r, 4)?;
        } else {
            *value = 0;
        }

        Ok(())
    }

    fn parse_quantization_params(r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        let quant = &mut hdr.quant;

        quant.base_q_idx = r.read_u8(8)?;

        Self::read_delta_q(r, &mut quant.delta_q_y_dc)?;
        Self::read_delta_q(r, &mut quant.delta_q_uv_dc)?;
        Self::read_delta_q(r, &mut quant.delta_q_uv_ac)?;

        hdr.lossless = quant.base_q_idx == 0
            && quant.delta_q_y_dc == 0
            && quant.delta_q_uv_dc == 0
            && quant.delta_q_uv_ac == 0;

        Ok(())
    }

    fn read_prob(r: &mut BitReader) -> Result<u8> {
        let prob_coded = r.read_bool()?;

        let prob = if prob_coded { r.read_u8(8)? } else { 255 };

        Ok(prob)
    }

    fn parse_segmentation_params(r: &mut BitReader, seg: &mut SegmentationParams) -> Result<()> {
        const SEGMENTATION_FEATURE_BITS: [u8; SEG_LVL_MAX] = [8, 6, 2, 0];
        const SEGMENTATION_FEATURE_SIGNED: [bool; SEG_LVL_MAX] = [true, true, false, false];

        seg.update_map = false;
        seg.update_data = false;

        seg.enabled = r.read_bool()?;

        if !seg.enabled {
            return Ok(());
        }

        seg.update_map = r.read_bool()?;

        if seg.update_map {
            for i in 0..SEG_TREE_PROBS {
                seg.tree_probs[i] = Self::read_prob(r)?;
            }

            seg.temporal_update = r.read_bool()?;

            for i in 0..PREDICTION_PROBS {
                seg.pred_probs[i] = if seg.temporal_update {
                    Self::read_prob(r)?
                } else {
                    255
                };
            }
        }

        seg.update_data = r.read_bool()?;

        if seg.update_data {
            seg.abs_or_delta_update = r.read_bool()?;
            for i in 0..MAX_SEGMENTS {
                for j in 0..SEG_LVL_MAX {
                    seg.feature_enabled[i][j] = r.read_bool()?;
                    if seg.feature_enabled[i][j] {
                        let bits_to_read = SEGMENTATION_FEATURE_BITS[j];
                        let mut feature_value = r.read_i16(bits_to_read)?;

                        if SEGMENTATION_FEATURE_SIGNED[j] {
                            let feature_sign = r.read_bool()?;

                            if feature_sign {
                                feature_value = -feature_value;
                            }
                        }

                        seg.feature_data[i][j] = feature_value;
                    }
                }
            }
        }

        Ok(())
    }

    fn calc_min_log2_tile_cols(sb64_cols: u32) -> i32 {
        let mut min_log2 = 0;

        while (MAX_TILE_WIDTH_B64 << min_log2) < sb64_cols {
            min_log2 += 1;
        }

        min_log2
    }

    fn calc_max_log2_tile_cols(sb64_cols: u32) -> i32 {
        let mut max_log2 = 1;

        while (sb64_cols >> max_log2) >= MIN_TILE_WIDTH_B64 {
            max_log2 += 1;
        }

        max_log2 - 1
    }

    fn parse_tile_info(&mut self, r: &mut BitReader, hdr: &mut Header) -> Result<()> {
        let min_log2_tile_cols = Self::calc_min_log2_tile_cols(self.sb64_cols);
        let max_log2_tile_cols = Self::calc_max_log2_tile_cols(self.sb64_cols);

        hdr.tile_cols_log2 = min_log2_tile_cols.try_into().unwrap();

        while hdr.tile_cols_log2 < max_log2_tile_cols.try_into().unwrap() {
            let increment_tile_cols_log2 = r.read_bool()?;

            if increment_tile_cols_log2 {
                hdr.tile_cols_log2 += 1;
            } else {
                break;
            }
        }

        hdr.tile_rows_log2 = r.read_u8(1)?;

        if hdr.tile_rows_log2 > 0 {
            let increment_tile_rows_log2 = r.read_bool()?;
            hdr.tile_rows_log2 += increment_tile_rows_log2 as u8;
        }

        Ok(())
    }

    fn parse_frame_header(&mut self, resource: impl AsRef<[u8]>, offset: usize) -> Result<Header> {
        let data = &resource.as_ref()[offset..];
        let mut r = BitReader::new(data);
        let mut hdr = Header::default();

        Self::parse_frame_marker(&mut r)?;
        Self::parse_profile(&mut r, &mut hdr)?;

        hdr.show_existing_frame = r.read_bool()?;

        if hdr.show_existing_frame {
            hdr.frame_to_show_map_idx = r.read_u8(3)?;
            return Ok(hdr);
        }

        hdr.frame_type =
            FrameType::n(r.read_u8(1)?).ok_or(anyhow!("Broken data: invalid frame type"))?;

        hdr.show_frame = r.read_bool()?;
        hdr.error_resilient_mode = r.read_bool()?;

        let frame_is_intra;

        if matches!(hdr.frame_type, FrameType::KeyFrame) {
            Self::parse_frame_sync_code(&mut r)?;
            self.parse_color_config(&mut r, &mut hdr)?;
            self.parse_frame_size(&mut r, &mut hdr)?;
            self.parse_render_size(&mut r, &mut hdr)?;
            hdr.refresh_frame_flags = 0xff;
            frame_is_intra = true;
        } else {
            if !hdr.show_frame {
                hdr.intra_only = r.read_bool()?;
            }

            frame_is_intra = hdr.intra_only;

            if !hdr.error_resilient_mode {
                hdr.reset_frame_context = r.read_u8(2)?;
            } else {
                hdr.reset_frame_context = 0;
            }

            if hdr.intra_only {
                Self::parse_frame_sync_code(&mut r)?;

                if !matches!(hdr.profile, Profile::Profile0) {
                    self.parse_color_config(&mut r, &mut hdr)?;
                } else {
                    hdr.color_space = ColorSpace::Bt601;
                    hdr.subsampling_x = true;
                    hdr.subsampling_y = true;
                    hdr.bit_depth = BitDepth::Depth8;

                    self.color_space = hdr.color_space;
                    self.subsampling_x = hdr.subsampling_x;
                    self.subsampling_y = hdr.subsampling_y;
                    self.bit_depth = hdr.bit_depth;
                }

                hdr.refresh_frame_flags = r.read_u8(8)?;
                self.parse_frame_size(&mut r, &mut hdr)?;
                self.parse_render_size(&mut r, &mut hdr)?;
            } else {
                // Copy from our cached version
                hdr.color_space = self.color_space;
                hdr.color_range = self.color_range;
                hdr.subsampling_x = self.subsampling_x;
                hdr.subsampling_y = self.subsampling_y;
                hdr.bit_depth = self.bit_depth;

                hdr.refresh_frame_flags = r.read_u8(8)?;

                for i in 0..REFS_PER_FRAME {
                    hdr.ref_frame_idx[i] = r.read_u8(3)?;
                    hdr.ref_frame_sign_bias[ReferenceFrameType::Last as usize + i] =
                        r.read_u8(1)?;
                }

                self.parse_frame_size_with_refs(&mut r, &mut hdr)?;
                hdr.allow_high_precision_mv = r.read_bool()?;
                Self::read_interpolation_filter(&mut r, &mut hdr)?;
            }
        }

        if !hdr.error_resilient_mode {
            hdr.refresh_frame_context = r.read_bool()?;
            hdr.frame_parallel_decoding_mode = r.read_bool()?;
        } else {
            hdr.refresh_frame_context = false;
            hdr.frame_parallel_decoding_mode = true;
        }

        hdr.frame_context_idx = r.read_u8(2)?;

        if frame_is_intra || hdr.error_resilient_mode {
            self.setup_past_independence(&mut hdr);
        }

        Self::parse_loop_filter_params(&mut r, &mut self.lf)?;
        Self::parse_quantization_params(&mut r, &mut hdr)?;
        Self::parse_segmentation_params(&mut r, &mut self.seg)?;
        self.parse_tile_info(&mut r, &mut hdr)?;

        hdr.header_size_in_bytes = r.read_u16(16)?;

        hdr.lf = self.lf.clone();
        hdr.seg = self.seg.clone();

        for i in 0..REF_FRAMES {
            let flag = 1 << i;
            if hdr.refresh_frame_flags & flag != 0 {
                self.reference_frame_sz[i].width = hdr.width;
                self.reference_frame_sz[i].height = hdr.height;
            }
        }

        hdr.uncompressed_header_size_in_bytes = (r.position() as u16 + 7) / 8;

        Ok(hdr)
    }

    /// Parse a single VP9 frame.
    pub fn parse_frame<T: AsRef<[u8]>>(
        &mut self,
        bitstream: T,
        offset: usize,
        size: usize,
    ) -> Result<Frame<T>> {
        let header = self.parse_frame_header(&bitstream, offset)?;

        Ok(Frame {
            header,
            bitstream,
            offset,
            size,
        })
    }

    /// Parses VP9 frames from the data in `resource`. This can result in more than one frame if the
    /// data passed in contains a VP9 superframe.
    pub fn parse_chunk<T: AsRef<[u8]>>(
        &mut self,
        resource: impl Fn() -> T,
    ) -> Result<Vec<Frame<T>>> {
        let superframe_hdr = self.parse_superframe_hdr(resource())?;
        let mut offset = 0;

        let mut frames = vec![];

        for i in 0..superframe_hdr.frames_in_superframe {
            let frame_sz = superframe_hdr.frame_sizes[i as usize];
            let frame = self.parse_frame(resource(), offset, frame_sz)?;
            offset += frame_sz;
            frames.push(frame);
        }

        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Buf;
    use std::io::Cursor;
    use std::io::Read;
    use std::io::Seek;

    use crate::decoders::vp9::parser::BitDepth;
    use crate::decoders::vp9::parser::ColorSpace;
    use crate::decoders::vp9::parser::FrameType;
    use crate::decoders::vp9::parser::InterpolationFilter;
    use crate::decoders::vp9::parser::Parser;
    use crate::decoders::vp9::parser::Profile;
    use crate::decoders::vp9::parser::MAX_SEGMENTS;
    use crate::decoders::vp9::parser::SEG_LVL_MAX;

    /// Read and return the data from the next IVF packet. Returns `None` if there is no more data
    /// to read.
    /// TODO: reuse the vp8 implementation for this function.
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
    fn test_parse_vp9_superframe() {
        // Demuxed, raw vp9 superframe
        const VP9_TEST_SUPERFRAME: &[u8] = include_bytes!("test_data/vp9-superframe.bin");

        let mut parser = Parser::default();
        let frames = parser
            .parse_chunk(|| VP9_TEST_SUPERFRAME)
            .expect("Parsing a superframe failed");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].size, 1333);
        assert_eq!(frames[1].offset, 1333);
        assert_eq!(frames[1].size, 214);
    }

    #[test]
    fn test_parse_test25fps_vp9() {
        // Muxed as IVF
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-25fps.vp9");

        let mut cursor = Cursor::new(TEST_STREAM);
        let mut parser = Parser::default();

        // Skip the IVH header entirely.
        cursor.seek(std::io::SeekFrom::Start(32)).unwrap();

        let mut frame_n = 0;
        while let Some(packet) = read_ivf_packet(&mut cursor) {
            let frames = parser
                .parse_chunk(|| packet.as_ref())
                .expect("Parsing a superframe failed");

            if frame_n == 0 {
                assert_eq!(frames.len(), 1);
                let h = &frames[0].header;

                assert!(matches!(h.profile, Profile::Profile0));
                assert!(matches!(h.bit_depth, BitDepth::Depth8));

                assert!(h.subsampling_x);
                assert!(h.subsampling_y);

                assert!(matches!(h.color_space, ColorSpace::Unknown));
                assert!(matches!(
                    h.color_range,
                    crate::decoders::vp9::parser::ColorRange::StudioSwing
                ));

                assert!(!h.show_existing_frame);
                assert_eq!(h.frame_to_show_map_idx, 0);

                assert!(matches!(h.frame_type, FrameType::KeyFrame));
                assert!(h.show_frame);
                assert!(!h.error_resilient_mode);

                assert_eq!(h.width, 320);
                assert_eq!(h.height, 240);

                assert!(!h.render_and_frame_size_different);

                assert_eq!(h.render_width, 320);
                assert_eq!(h.render_height, 240);

                assert!(!h.intra_only);
                assert_eq!(h.reset_frame_context, 0);

                assert_eq!(h.refresh_frame_flags, 0xff);
                assert_eq!(h.ref_frame_idx, [0, 0, 0]);
                assert_eq!(h.ref_frame_sign_bias, [0, 0, 0, 0]);

                assert!(!h.allow_high_precision_mv);
                assert!(matches!(
                    h.interpolation_filter,
                    InterpolationFilter::EightTap
                ));

                assert!(h.refresh_frame_context);
                assert!(h.frame_parallel_decoding_mode);
                assert_eq!(h.frame_context_idx, 0);

                let lf = &h.lf;
                assert_eq!(lf.level, 9);
                assert_eq!(lf.sharpness, 0);

                assert!(lf.delta_enabled);
                assert!(lf.delta_update);

                assert_eq!(lf.update_ref_delta, [true, false, true, true]);
                assert_eq!(lf.ref_deltas, [1, 0, -1, -1]);

                assert_eq!(lf.update_mode_delta, [false, false]);

                let q = &h.quant;

                assert_eq!(q.base_q_idx, 65);
                assert_eq!(q.delta_q_y_dc, 0);
                assert_eq!(q.delta_q_uv_dc, 0);
                assert_eq!(q.delta_q_uv_ac, 0);

                let s = &h.seg;

                assert!(!s.enabled);
                assert!(!s.update_map);
                assert_eq!(s.tree_probs, [0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(s.pred_probs, [0, 0, 0]);
                assert!(!s.temporal_update);
                assert!(!s.update_data);
                assert!(!s.abs_or_delta_update);
                assert_eq!(s.feature_enabled, [[false; SEG_LVL_MAX]; MAX_SEGMENTS]);
                assert_eq!(s.feature_data, [[0; SEG_LVL_MAX]; MAX_SEGMENTS]);

                assert_eq!(h.tile_cols_log2, 0);
                assert_eq!(h.tile_rows_log2, 0);
                assert_eq!(h.header_size_in_bytes, 120);

                assert!(!h.lossless);
            } else if frame_n == 1 {
                assert_eq!(frames.len(), 2);

                assert_eq!(frames[0].offset, 0);
                assert_eq!(frames[0].size, 2390);
                assert_eq!(frames[1].offset, 2390);
                assert_eq!(frames[1].size, 108);

                let h = &frames[0].header;

                assert!(matches!(h.profile, Profile::Profile0));
                assert!(matches!(h.bit_depth, BitDepth::Depth8));

                assert!(h.subsampling_x);
                assert!(h.subsampling_y);

                assert!(matches!(h.color_space, ColorSpace::Unknown));
                assert!(matches!(
                    h.color_range,
                    crate::decoders::vp9::parser::ColorRange::StudioSwing
                ));

                assert!(!h.show_existing_frame);
                assert_eq!(h.frame_to_show_map_idx, 0);

                assert!(matches!(h.frame_type, FrameType::InterFrame));
                assert!(!h.show_frame);
                assert!(!h.error_resilient_mode);

                assert_eq!(h.width, 320);
                assert_eq!(h.height, 240);

                assert!(!h.render_and_frame_size_different);

                assert_eq!(h.render_width, 320);
                assert_eq!(h.render_height, 240);

                assert!(!h.intra_only);
                assert_eq!(h.reset_frame_context, 0);

                assert_eq!(h.refresh_frame_flags, 4);
                assert_eq!(h.ref_frame_idx, [0, 1, 2]);
                assert_eq!(h.ref_frame_sign_bias, [0, 0, 0, 0]);

                assert!(h.allow_high_precision_mv);
                assert!(matches!(
                    h.interpolation_filter,
                    InterpolationFilter::EightTap
                ));

                assert!(h.refresh_frame_context);
                assert!(h.frame_parallel_decoding_mode);
                assert_eq!(h.frame_context_idx, 1);

                let lf = &h.lf;
                assert_eq!(lf.level, 15);
                assert_eq!(lf.sharpness, 0);

                assert!(lf.delta_enabled);
                assert!(!lf.delta_update);

                assert_eq!(lf.update_ref_delta, [true, false, true, true]);
                assert_eq!(lf.ref_deltas, [1, 0, -1, -1]);

                assert_eq!(lf.update_mode_delta, [false, false]);

                let q = &h.quant;

                assert_eq!(q.base_q_idx, 112);
                assert_eq!(q.delta_q_y_dc, 0);
                assert_eq!(q.delta_q_uv_dc, 0);
                assert_eq!(q.delta_q_uv_ac, 0);

                let s = &h.seg;

                assert!(!s.enabled);
                assert!(!s.update_map);
                assert_eq!(s.tree_probs, [0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(s.pred_probs, [0, 0, 0]);
                assert!(!s.temporal_update);
                assert!(!s.update_data);
                assert!(!s.abs_or_delta_update);
                assert_eq!(s.feature_enabled, [[false; SEG_LVL_MAX]; MAX_SEGMENTS]);
                assert_eq!(s.feature_data, [[0; SEG_LVL_MAX]; MAX_SEGMENTS]);

                assert_eq!(h.tile_cols_log2, 0);
                assert_eq!(h.tile_rows_log2, 0);
                assert_eq!(h.header_size_in_bytes, 48);

                assert!(!h.lossless);

                let h = &frames[1].header;

                assert!(matches!(h.profile, Profile::Profile0));
                assert!(matches!(h.bit_depth, BitDepth::Depth8));

                assert!(h.subsampling_x);
                assert!(h.subsampling_y);

                assert!(matches!(h.color_space, ColorSpace::Unknown));
                assert!(matches!(
                    h.color_range,
                    crate::decoders::vp9::parser::ColorRange::StudioSwing
                ));

                assert!(!h.show_existing_frame);
                assert_eq!(h.frame_to_show_map_idx, 0);

                assert!(matches!(h.frame_type, FrameType::InterFrame));
                assert!(h.show_frame);
                assert!(!h.error_resilient_mode);

                assert_eq!(h.width, 320);
                assert_eq!(h.height, 240);

                assert!(!h.render_and_frame_size_different);

                assert_eq!(h.render_width, 320);
                assert_eq!(h.render_height, 240);

                assert!(!h.intra_only);
                assert_eq!(h.reset_frame_context, 0);

                assert_eq!(h.refresh_frame_flags, 1);
                assert_eq!(h.ref_frame_idx, [0, 1, 2]);
                assert_eq!(h.ref_frame_sign_bias, [0, 0, 0, 1]);

                assert!(!h.allow_high_precision_mv);
                assert!(matches!(
                    h.interpolation_filter,
                    InterpolationFilter::EightTap
                ));

                assert!(h.refresh_frame_context);
                assert!(h.frame_parallel_decoding_mode);
                assert_eq!(h.frame_context_idx, 0);

                let lf = &h.lf;
                assert_eq!(lf.level, 36);
                assert_eq!(lf.sharpness, 0);

                assert!(lf.delta_enabled);
                assert!(!lf.delta_update);

                assert_eq!(lf.update_ref_delta, [true, false, true, true]);
                assert_eq!(lf.ref_deltas, [1, 0, -1, -1]);

                assert_eq!(lf.update_mode_delta, [false, false]);

                let q = &h.quant;

                assert_eq!(q.base_q_idx, 216);
                assert_eq!(q.delta_q_y_dc, 0);
                assert_eq!(q.delta_q_uv_dc, 0);
                assert_eq!(q.delta_q_uv_ac, 0);

                let s = &h.seg;

                assert!(!s.enabled);
                assert!(!s.update_map);
                assert_eq!(s.tree_probs, [0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(s.pred_probs, [0, 0, 0]);
                assert!(!s.temporal_update);
                assert!(!s.update_data);
                assert!(!s.abs_or_delta_update);
                assert_eq!(s.feature_enabled, [[false; SEG_LVL_MAX]; MAX_SEGMENTS]);
                assert_eq!(s.feature_data, [[0; SEG_LVL_MAX]; MAX_SEGMENTS]);

                assert_eq!(h.tile_cols_log2, 0);
                assert_eq!(h.tile_rows_log2, 0);
                assert_eq!(h.header_size_in_bytes, 9);

                assert!(!h.lossless);
            }

            frame_n += 1;
        }
    }
}

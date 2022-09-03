// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::io::Cursor;

use anyhow::{anyhow, Result};
use bytes::Buf;
use log::debug;

use crate::decoders::vp8::bool_decoder::BoolDecoder;
use crate::decoders::vp8::probs::COEFF_DEFAULT_PROBS;
use crate::decoders::vp8::probs::COEFF_UPDATE_PROBS;
use crate::decoders::vp8::probs::KF_UV_MODE_PROBS;
use crate::decoders::vp8::probs::KF_Y_MODE_PROBS;
use crate::decoders::vp8::probs::MV_DEFAULT_PROBS;
use crate::decoders::vp8::probs::MV_UPDATE_PROBS;
use crate::decoders::vp8::probs::NK_UV_MODE_PROBS;
use crate::decoders::vp8::probs::NK_Y_MODE_PROBS;

/// Dequantization indices as parsed from the quant_indices() syntax.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuantIndices {
    /// The dequantization table index used for the luma AC coefficients (and
    /// other coefficient groups if no delta value is present).
    pub y_ac_qi: u8,
    /// Indicates the delta value that is added to the baseline index to obtain
    /// the luma DC coefficient dequantization index.
    pub y_dc_delta: i8,
    /// Indicates the delta value that is added to the baseline index to obtain
    /// the Y2 block DC coefficient dequantization index.
    pub y2_dc_delta: i8,
    /// Indicates the delta value that is added to the baseline index to obtain
    /// the Y2 block AC coefficient dequantization index.
    pub y2_ac_delta: i8,
    /// Indicates the delta value that is added to the baseline index to obtain
    /// the chroma DC coefficient dequantization index.
    pub uv_dc_delta: i8,
    /// Indicates the delta value that is added to the baseline index to obtain
    /// the chroma AC coefficient dequantization index.
    pub uv_ac_delta: i8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MbLfAdjustments {
    /// Indicates if the MB-level loop filter adjustment (based on the used
    /// reference frame and coding mode) is on for the current frame.
    pub loop_filter_adj_enable: bool,
    /// Indicates if the delta values used in adjustment are updated in the
    /// current frame.
    pub mode_ref_lf_delta_update: bool,

    //if mode_ref_lf_delta_update == 1
    /// Indicates the adjustment delta value corresponding to a certain used
    /// reference frame.
    pub ref_frame_delta: [i8; 4],
    /// Indicates the adjustment delta value corresponding to a certain MB
    /// prediction mode
    pub mb_mode_delta: [i8; 4],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Segmentation {
    /// Enables the segmentation feature for the current frame.
    pub segmentation_enabled: bool,
    /// Determines if the MB segmentation map is updated in the current frame.
    pub update_mb_segmentation_map: bool,
    /// indicates if the segment feature data is updated in the current frame.
    pub update_segment_feature_data: bool,

    // If update_segment_feature_data == 1
    /// Indicates the feature data update mode, O for delta and 1 for the
    /// absolute value.
    pub segment_feature_mode: bool,
    /// Indicates if the quantizer value is updated for the izh segment.
    pub quantizer_update_value: [i8; 4],
    /// Indicates the update value for the loop filter level.
    pub lf_update_value: [i8; 4],

    // if update_mb_segmentation_map == 1
    /// The branch probabilities of the segment id decoding tree.
    pub segment_prob: [u8; 3],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModeProbs {
    /// Branch probabilities of the luma intra prediction mode decoding tree,
    /// kept live between frames.
    pub intra_16x16_prob: [u8; 4],
    /// Branch probabilities of the chroma intra prediction mode decoding tree,
    /// kept live between frames.
    pub intra_chroma_prob: [u8; 3],
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Indicates if the current frame is a key frame or not.
    key_frame: bool,
    /// Determines the bitstream version.
    version: u8,
    /// Indicates if the current frame is meant to be displayed or not.
    show_frame: bool,
    /// The size in bytes of the Uncompressed Data Chunk
    data_chunk_size: u8,
    /// Determines the size of the first partition (control partition) excluding
    /// the size of the Uncompressed Data Chunk
    first_part_size: u32,

    /// The frame's width, in pixels.
    width: u16,
    /// The frame's height, in pixels.
    height: u16,
    /// Horizontal scale code value.
    horiz_scale_code: u8,
    /// Vertical scale code value.
    vert_scale_code: u8,
    /// Defines the YUV color space of the sequence.
    color_space: bool,
    /// Specifies if the decoder is required to clamp the reconstructed pixel
    /// values.
    clamping_type: bool,
    /// Determines whether the normal or the simple loop filter is used.
    filter_type: bool,
    /// Controls the deblocking filter.
    loop_filter_level: u8,
    /// Controls the deblocking filter.
    sharpness_level: u8,
    /// Determines the number of separate partitions containing the DCT
    /// coefficients of the macroblocks.
    log2_nbr_of_dct_partitions: u8,

    partition_size: [u32; 8],

    /// Dequantizer indices.
    quant_indices: QuantIndices,

    /// Determines whether updated token probabilities are used only for this
    /// frame or until further update
    refresh_entropy_probs: bool,
    /// Determines if the current decoded frame refreshes the last frame
    /// reference buffer
    refresh_last: bool,

    /// Determines if the current decoded frame refreshes the golden frame.
    refresh_golden_frame: bool,
    /// Determines if the current decoded frame refreshes the alternate
    /// reference frame.
    refresh_alternate_frame: bool,
    /// Determines if the golden reference is replaced by another reference.
    copy_buffer_to_golden: u8,
    /// Determines if the alternate reference is replaced by another reference.
    copy_buffer_to_alternate: u8,
    /// Controls the sign of motion vectors when the golden frame is referenced.
    sign_bias_golden: bool,
    /// Controls the sign of motion vectors when the alternate frame is
    /// referenced.
    sign_bias_alternate: bool,

    /// The new branch probability for the DCT/WHT tree.
    coeff_prob: [[[[u8; 11]; 3]; 8]; 4],
    /// MV decoding probability.
    mv_prob: [[u8; 19]; 2],

    /// Enables or disables the skipping of macroblocks containing no non-zero
    /// coefficients.
    mb_no_coeff_skip: bool,
    /// The probability that the macroblock is not skipped (flag indicating
    /// skipped macroblock is false).
    prob_skip_false: u8,
    /// The probability of an intra macroblock.
    prob_intra: u8,
    /// The probability that the last reference frame is used for inter
    /// prediction.
    prob_last: u8,
    /// The probability that the golden reference frame is used for inter
    /// prediction.
    prob_golden: u8,
    /// Branch probabilities kept live across frames.
    mode_probs: ModeProbs,

    /// Boolean decoder `range` for this frame.
    bd_range: usize,
    /// Boolean decoder `value` for this frame.
    bd_value: usize,
    /// Boolean decoder `count` for this frame.
    bd_count: isize,

    /// The size in bits of the Frame Header, thus excluding any Uncompressed
    /// Data Chunk bytes.
    header_size: u32,
}

#[allow(dead_code)]
impl Header {
    /// Get a reference to the header's key frame.
    pub fn key_frame(&self) -> bool {
        self.key_frame
    }

    /// Get a reference to the header's version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Get a reference to the header's show frame.
    pub fn show_frame(&self) -> bool {
        self.show_frame
    }

    /// Get a reference to the header's data chunk size.
    pub fn data_chunk_size(&self) -> u8 {
        self.data_chunk_size
    }

    /// Get a reference to the header's first part size.
    pub fn first_part_size(&self) -> u32 {
        self.first_part_size
    }

    /// Get a reference to the header's width.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Get a reference to the header's height.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// Get a reference to the header's horiz scale code.
    pub fn horiz_scale_code(&self) -> u8 {
        self.horiz_scale_code
    }

    /// Get a reference to the header's vert scale code.
    pub fn vert_scale_code(&self) -> u8 {
        self.vert_scale_code
    }

    /// Get a reference to the header's color space.
    pub fn color_space(&self) -> bool {
        self.color_space
    }

    /// Get a reference to the header's clamping type.
    pub fn clamping_type(&self) -> bool {
        self.clamping_type
    }

    /// Get a reference to the header's filter type.
    pub fn filter_type(&self) -> bool {
        self.filter_type
    }

    /// Get a reference to the header's loop filter level.
    pub fn loop_filter_level(&self) -> u8 {
        self.loop_filter_level
    }

    /// Get a reference to the header's sharpness level.
    pub fn sharpness_level(&self) -> u8 {
        self.sharpness_level
    }

    /// Get a reference to the header's log2 nbr of dct partitions.
    pub fn log2_nbr_of_dct_partitions(&self) -> u8 {
        self.log2_nbr_of_dct_partitions
    }

    /// Get a reference to the header's partition size.
    pub fn partition_size(&self) -> [u32; 8] {
        self.partition_size
    }

    /// Get a reference to the header's quant indices.
    pub fn quant_indices(&self) -> &QuantIndices {
        &self.quant_indices
    }

    /// Get a reference to the header's refresh entropy probs.
    pub fn refresh_entropy_probs(&self) -> bool {
        self.refresh_entropy_probs
    }

    /// Get a reference to the header's refresh last.
    pub fn refresh_last(&self) -> bool {
        self.refresh_last
    }

    /// Get a reference to the header's refresh golden frame.
    pub fn refresh_golden_frame(&self) -> bool {
        self.refresh_golden_frame
    }

    /// Get a reference to the header's refresh alternate frame.
    pub fn refresh_alternate_frame(&self) -> bool {
        self.refresh_alternate_frame
    }

    /// Get a reference to the header's copy buffer to golden.
    pub fn copy_buffer_to_golden(&self) -> u8 {
        self.copy_buffer_to_golden
    }

    /// Get a reference to the header's copy buffer to alternate.
    pub fn copy_buffer_to_alternate(&self) -> u8 {
        self.copy_buffer_to_alternate
    }

    /// Get a reference to the header's sign bias golden.
    pub fn sign_bias_golden(&self) -> bool {
        self.sign_bias_golden
    }

    /// Get a reference to the header's sign bias alternate.
    pub fn sign_bias_alternate(&self) -> bool {
        self.sign_bias_alternate
    }

    /// Get a reference to the header's coeff prob.
    pub fn coeff_prob(&self) -> [[[[u8; 11]; 3]; 8]; 4] {
        self.coeff_prob
    }

    /// Get a reference to the header's mv prob.
    pub fn mv_prob(&self) -> [[u8; 19]; 2] {
        self.mv_prob
    }

    /// Get a reference to the header's mb no coeff skip.
    pub fn mb_no_coeff_skip(&self) -> bool {
        self.mb_no_coeff_skip
    }

    /// Get a reference to the header's prob skip false.
    pub fn prob_skip_false(&self) -> u8 {
        self.prob_skip_false
    }

    /// Get a reference to the header's prob intra.
    pub fn prob_intra(&self) -> u8 {
        self.prob_intra
    }

    /// Get a reference to the header's prob last.
    pub fn prob_last(&self) -> u8 {
        self.prob_last
    }

    /// Get a reference to the header's prob golden.
    pub fn prob_golden(&self) -> u8 {
        self.prob_golden
    }

    /// Get a reference to the header's mode probs.
    pub fn mode_probs(&self) -> &ModeProbs {
        &self.mode_probs
    }

    /// Get a reference to the header's bd range.
    pub fn bd_range(&self) -> usize {
        self.bd_range
    }

    /// Get a reference to the header's bd value.
    pub fn bd_value(&self) -> usize {
        self.bd_value
    }

    /// Get a reference to the header's bd count.
    pub fn bd_count(&self) -> isize {
        self.bd_count
    }

    /// Get a reference to the header's header size.
    pub fn header_size(&self) -> u32 {
        self.header_size
    }
}
/// A VP8 frame.
pub struct Frame<T: AsRef<[u8]>> {
    /// The abstraction for the raw memory for this frame.
    pub bitstream: T,
    /// The frame header.
    pub header: Header,
}

impl<T: AsRef<[u8]>> Frame<T> {
    /// Creates a new frame, using the resource as its backing memory.
    fn new(bitstream: T) -> Self {
        Self {
            bitstream,
            header: Default::default(),
        }
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Frame<T> {
    fn as_ref(&self) -> &[u8] {
        self.bitstream.as_ref()
    }
}

/// A VP8 parser based on GStreamer's vp8parser and Chromium's VP8 parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parser {
    /// Segmentation data kept live across frames.
    segmentation: Segmentation,
    /// MbLfAdjustments data kept live across frames.
    mb_lf_adjust: MbLfAdjustments,
    /// Coeff probabilities data kept live across frames.
    coeff_prob: [[[[u8; 11]; 3]; 8]; 4],
    /// Motion vector probabilities data kept live across frames.
    mv_prob: [[u8; 19]; 2],
    /// Branch probabilities kept live across frames.
    mode_probs: ModeProbs,
}

impl Parser {
    pub fn segmentation(&self) -> &Segmentation {
        &self.segmentation
    }

    pub fn mb_lf_adjust(&self) -> &MbLfAdjustments {
        &self.mb_lf_adjust
    }

    pub fn reset(&mut self) {
        *self = Default::default();
    }

    fn mode_probs_init_defaults(mode_probs: &mut ModeProbs, key_frame: bool) {
        if key_frame {
            mode_probs.intra_16x16_prob = KF_Y_MODE_PROBS;
            mode_probs.intra_chroma_prob = KF_UV_MODE_PROBS;
        } else {
            mode_probs.intra_16x16_prob = NK_Y_MODE_PROBS;
            mode_probs.intra_chroma_prob = NK_UV_MODE_PROBS;
        }
    }

    fn parse_uncompressed_data_chunk<T: AsRef<[u8]>>(
        &mut self,
        reader: &mut Cursor<T>,
        frame: &mut Header,
    ) -> Result<()> {
        debug!("Parsing VP8 uncompressed data chunk.");

        let frame_tag = reader.get_uint_le(3) as u32;

        frame.key_frame = (frame_tag & 0x1) == 0;
        frame.version = ((frame_tag >> 1) & 0x07) as u8;
        frame.show_frame = ((frame_tag >> 4) & 0x1) != 0;
        frame.first_part_size = (frame_tag >> 5) & 0x7ffff;

        if frame.key_frame {
            let start_code = reader.get_uint(3) as u32;

            if start_code != 0x9d012a {
                return Err(anyhow!("Invalid start code {}", start_code));
            }

            let size_code = reader.get_uint_le(2) as u16;
            frame.horiz_scale_code = (size_code >> 14) as u8;
            frame.width = size_code & 0x3fff;

            let size_code = reader.get_uint_le(2) as u16;
            frame.vert_scale_code = (size_code >> 14) as u8;
            frame.height = size_code & 0x3fff;

            // Reset on every key frame.
            self.reset();
        }

        frame.data_chunk_size = reader.position() as u8;
        Ok(())
    }

    fn update_segmentation<T: AsRef<[u8]>>(
        bd: &mut BoolDecoder<T>,
        seg: &mut Segmentation,
    ) -> Result<()> {
        seg.update_mb_segmentation_map = false;
        seg.update_segment_feature_data = false;

        seg.segmentation_enabled = bd.read_bool()?;
        if !seg.segmentation_enabled {
            return Ok(());
        }

        seg.update_mb_segmentation_map = bd.read_bool()?;
        seg.update_segment_feature_data = bd.read_bool()?;

        if seg.update_segment_feature_data {
            seg.segment_feature_mode = bd.read_bool()?;

            for value in seg.quantizer_update_value.iter_mut() {
                let update = bd.read_bool()?;
                if update {
                    *value = bd.read_sint(7)?;
                } else {
                    // quantizer_update_value defaults to zero if update flag is
                    // zero (Section 9.3, 4.b)
                    *value = 0;
                }
            }

            for value in seg.lf_update_value.iter_mut() {
                let update = bd.read_bool()?;
                if update {
                    *value = bd.read_sint(6)?;
                } else {
                    // lf_update_value defaults to zero if update flag is
                    // zero (Section 9.3, 4.b)
                    *value = 0;
                }
            }

            if seg.update_mb_segmentation_map {
                for value in seg.segment_prob.iter_mut() {
                    let update = bd.read_bool()?;
                    if update {
                        *value = bd.read_uint(8)?;
                    } else {
                        // segment_prob defaults to 255 if update flag is
                        // zero (Section 9.3, 5)
                        *value = 255;
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_mb_lf_adjustments<T: AsRef<[u8]>>(
        bd: &mut BoolDecoder<T>,
        adj: &mut MbLfAdjustments,
    ) -> Result<()> {
        adj.mode_ref_lf_delta_update = false;

        adj.loop_filter_adj_enable = bd.read_bool()?;
        if !adj.loop_filter_adj_enable {
            return Ok(());
        }

        adj.mode_ref_lf_delta_update = bd.read_bool()?;
        if !adj.mode_ref_lf_delta_update {
            return Ok(());
        }

        for value in adj.ref_frame_delta.iter_mut() {
            let update = bd.read_bool()?;
            if update {
                *value = bd.read_sint(6)?;
            }
        }

        for value in adj.mb_mode_delta.iter_mut() {
            let update = bd.read_bool()?;
            if update {
                *value = bd.read_sint(6)?;
            }
        }

        Ok(())
    }

    fn parse_quant_indices<T: AsRef<[u8]>>(
        bd: &mut BoolDecoder<T>,
        q: &mut QuantIndices,
    ) -> Result<()> {
        q.y_ac_qi = bd.read_uint(7)?;

        let y_dc_delta_present = bd.read_bool()?;

        if y_dc_delta_present {
            q.y_dc_delta = bd.read_sint(4)?;
        } else {
            q.y_dc_delta = 0;
        }

        let y2_dc_delta_present = bd.read_bool()?;
        if y2_dc_delta_present {
            q.y2_dc_delta = bd.read_sint(4)?;
        } else {
            q.y2_dc_delta = 0;
        }

        let y2_ac_delta_present = bd.read_bool()?;
        if y2_ac_delta_present {
            q.y2_ac_delta = bd.read_sint(4)?;
        } else {
            q.y2_ac_delta = 0;
        }

        let uv_dc_delta_present = bd.read_bool()?;
        if uv_dc_delta_present {
            q.uv_dc_delta = bd.read_sint(4)?;
        } else {
            q.uv_dc_delta = 0;
        }

        let uv_ac_delta_present = bd.read_bool()?;
        if uv_ac_delta_present {
            q.uv_ac_delta = bd.read_sint(4)?;
        } else {
            q.uv_ac_delta = 0;
        }

        Ok(())
    }

    fn parse_token_prob_update<T: AsRef<[u8]>>(
        bd: &mut BoolDecoder<T>,
        coeff_probs: &mut [[[[u8; 11]; 3]; 8]; 4],
    ) -> Result<()> {
        for (i, vi) in coeff_probs.iter_mut().enumerate() {
            for (j, vj) in vi.iter_mut().enumerate() {
                for (k, vk) in vj.iter_mut().enumerate() {
                    for (l, prob) in vk.iter_mut().enumerate() {
                        let update = bd.read_bool_with_prob(COEFF_UPDATE_PROBS[i][j][k][l])?;
                        if update {
                            *prob = bd.read_uint(8)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_mv_prob_update<T: AsRef<[u8]>>(
        bd: &mut BoolDecoder<T>,
        mv_probs: &mut [[u8; 19]; 2],
    ) -> Result<()> {
        for (i, vi) in mv_probs.iter_mut().enumerate() {
            for (j, prob) in vi.iter_mut().enumerate() {
                let update = bd.read_bool_with_prob(MV_UPDATE_PROBS[i][j])?;
                if update {
                    let mv_prob_update = bd.read_uint::<u8>(7)?;

                    if mv_prob_update > 0 {
                        *prob = mv_prob_update << 1;
                    } else {
                        *prob = 1;
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_frame_header(&mut self, data: &[u8], frame: &mut Header) -> Result<()> {
        debug!("Parsing VP8 frame header.");
        let mut bd = BoolDecoder::new(data);

        if frame.key_frame {
            frame.color_space = bd.read_bool()?;
            frame.clamping_type = bd.read_bool()?;
        }

        Parser::update_segmentation(&mut bd, &mut self.segmentation)?;

        frame.filter_type = bd.read_bool()?;
        frame.loop_filter_level = bd.read_uint(6)?;
        frame.sharpness_level = bd.read_uint(3)?;

        Parser::parse_mb_lf_adjustments(&mut bd, &mut self.mb_lf_adjust)?;

        frame.log2_nbr_of_dct_partitions = bd.read_uint(2)?;

        Parser::parse_quant_indices(&mut bd, &mut frame.quant_indices)?;

        frame.copy_buffer_to_golden = 0;
        frame.copy_buffer_to_alternate = 0;

        if frame.key_frame {
            frame.refresh_entropy_probs = bd.read_bool()?;

            frame.refresh_last = true;
            frame.refresh_golden_frame = true;
            frame.refresh_alternate_frame = true;

            Parser::mode_probs_init_defaults(&mut frame.mode_probs, true);
        } else {
            frame.refresh_golden_frame = bd.read_bool()?;
            frame.refresh_alternate_frame = bd.read_bool()?;

            if !frame.refresh_golden_frame {
                frame.copy_buffer_to_golden = bd.read_uint(2)?;
            }

            if !frame.refresh_alternate_frame {
                frame.copy_buffer_to_alternate = bd.read_uint(2)?;
            }

            frame.sign_bias_golden = bd.read_bool()?;
            frame.sign_bias_alternate = bd.read_bool()?;
            frame.refresh_entropy_probs = bd.read_bool()?;
            frame.refresh_last = bd.read_bool()?;

            frame.mode_probs = self.mode_probs.clone();
        }

        frame.coeff_prob = self.coeff_prob;
        frame.mv_prob = self.mv_prob;

        Parser::parse_token_prob_update(&mut bd, &mut frame.coeff_prob)?;

        frame.mb_no_coeff_skip = bd.read_bool()?;
        if frame.mb_no_coeff_skip {
            frame.prob_skip_false = bd.read_uint(8)?;
        }

        if !frame.key_frame {
            frame.prob_intra = bd.read_uint(8)?;
            frame.prob_last = bd.read_uint(8)?;
            frame.prob_golden = bd.read_uint(8)?;

            let intra_16x16_prob_update_flag = bd.read_bool()?;
            if intra_16x16_prob_update_flag {
                for prob in frame.mode_probs.intra_16x16_prob.iter_mut() {
                    *prob = bd.read_uint(8)?;
                }
            }

            let intra_chroma_prob_update_flag = bd.read_bool()?;
            if intra_chroma_prob_update_flag {
                for prob in frame.mode_probs.intra_chroma_prob.iter_mut() {
                    *prob = bd.read_uint(8)?;
                }
            }

            Parser::parse_mv_prob_update(&mut bd, &mut frame.mv_prob)?;
        }

        if frame.refresh_entropy_probs {
            self.coeff_prob = frame.coeff_prob;
            self.mv_prob = frame.mv_prob;

            if !frame.key_frame {
                self.mode_probs = frame.mode_probs.clone();
            }
        }

        frame.header_size = bd.pos() as u32;
        Parser::sync_bd_state(&bd, frame);

        Ok(())
    }

    fn compute_partition_sizes(frame: &mut Header, data: &[u8]) -> Result<()> {
        let num_partitions = usize::try_from(1 << frame.log2_nbr_of_dct_partitions)?;
        let mut part_size_ofs = usize::try_from(frame.first_part_size)?;
        let mut ofs = part_size_ofs + 3 * (num_partitions - 1);

        if ofs > data.len() {
            return Err(anyhow!("Not enough bytes left to parse partition sizes.",));
        }

        for i in 0..num_partitions - 1 {
            let b0 = u32::from(data[part_size_ofs + 0]);
            let b1 = u32::from(data[part_size_ofs + 1]) << 8;
            let b2 = u32::from(data[part_size_ofs + 2]) << 16;

            let part_size = usize::try_from(b0 | b1 | b2)?;
            part_size_ofs += 3;

            frame.partition_size[i] = u32::try_from(part_size)?;
            ofs += part_size;
        }

        if ofs > data.len() {
            return Err(anyhow!(
                "Not enough bytes left to determine the last partition size",
            ));
        }

        frame.partition_size[num_partitions - 1] = u32::try_from(data.len() - ofs)?;
        Ok(())
    }

    fn sync_bd_state<T: AsRef<[u8]>>(bd: &BoolDecoder<T>, frame: &mut Header) {
        frame.bd_range = bd.range();
        frame.bd_value = bd.value();
        frame.bd_count = bd.count();
    }

    /// Parse a single frame from the chunk in `data`.
    pub fn parse_frame<T: AsRef<[u8]>>(&mut self, resource: T) -> Result<Frame<T>> {
        let mut frame = Frame::new(resource);
        let mut reader = Cursor::new(frame.bitstream.as_ref());

        self.parse_uncompressed_data_chunk(&mut reader, &mut frame.header)?;

        let data = frame.bitstream.as_ref();

        if usize::from(frame.header.data_chunk_size)
            + usize::try_from(frame.header.first_part_size)?
            > data.len()
        {
            return Err(anyhow!("Broken data"));
        }

        let data = &data[frame.header.data_chunk_size as usize..];

        self.parse_frame_header(data, &mut frame.header)?;
        Parser::compute_partition_sizes(&mut frame.header, data)?;

        Ok(frame)
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            segmentation: Default::default(),
            mb_lf_adjust: Default::default(),
            coeff_prob: COEFF_DEFAULT_PROBS,
            mv_prob: MV_DEFAULT_PROBS,
            mode_probs: ModeProbs {
                intra_16x16_prob: NK_Y_MODE_PROBS,
                intra_chroma_prob: NK_UV_MODE_PROBS,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Parser;

    // Test and test data extracted from GStreamer
    // subprojects/gst-plugins-bad/tests/check/libs/vp8parser.c
    const VP8_TEST_0_INTRA: &[u8] = include_bytes!("test_data/vp8-parser-test-0-intra.bin");
    const VP8_TEST_0_INTER: &[u8] = include_bytes!("test_data/vp8-parser-test-0-inter.bin");

    #[test]
    fn gst_vp8parser_test_intra() {
        let mut parser = Parser::default();
        let frame = parser
            .parse_frame(VP8_TEST_0_INTRA)
            .expect("Parsing a intra frame failed");

        assert!(frame.header.key_frame);

        assert_eq!(frame.header.first_part_size, 234);
        assert_eq!(frame.header.width, 176);
        assert_eq!(frame.header.height, 144);

        assert!(parser.mb_lf_adjust.loop_filter_adj_enable);
        assert!(parser.mb_lf_adjust.mode_ref_lf_delta_update);

        assert_eq!(parser.mb_lf_adjust.ref_frame_delta[0], 2);
        assert_eq!(parser.mb_lf_adjust.ref_frame_delta[1], 0);
        assert_eq!(parser.mb_lf_adjust.ref_frame_delta[2], -2);
        assert_eq!(parser.mb_lf_adjust.ref_frame_delta[3], -2);

        assert_eq!(parser.mb_lf_adjust.mb_mode_delta[0], 4);
        assert_eq!(parser.mb_lf_adjust.mb_mode_delta[1], -2);
        assert_eq!(parser.mb_lf_adjust.mb_mode_delta[2], 2);
        assert_eq!(parser.mb_lf_adjust.mb_mode_delta[3], 4);

        assert_eq!(frame.header.quant_indices.y_ac_qi, 4);
        assert!(frame.header.mb_no_coeff_skip);

        assert_eq!(frame.header.bd_range, 0xe8);
        assert_eq!(frame.header.bd_value, 0x68);
        assert_eq!(frame.header.bd_count, 1);
    }

    #[test]
    fn gst_vp8parser_test_inter() {
        let mut parser = Parser::default();
        let frame = parser
            .parse_frame(VP8_TEST_0_INTER)
            .expect("Parsing a inter frame failed");

        assert!(!frame.header.key_frame);

        assert_eq!(frame.header.first_part_size, 98);
        assert!(parser.mb_lf_adjust.loop_filter_adj_enable);
        assert_eq!(frame.header.quant_indices.y_ac_qi, 4);

        assert!(frame.header.refresh_entropy_probs);
        assert!(frame.header.refresh_last);
        assert!(frame.header.mb_no_coeff_skip);

        assert_eq!(frame.header.prob_skip_false, 131);
        assert_eq!(frame.header.prob_intra, 224);
        assert_eq!(frame.header.prob_last, 233);
        assert_eq!(frame.header.prob_golden, 1);

        assert_eq!(frame.header.bd_range, 0x8e);
        assert_eq!(frame.header.bd_value, 0x85);
        assert_eq!(frame.header.bd_count, 5);
    }
}

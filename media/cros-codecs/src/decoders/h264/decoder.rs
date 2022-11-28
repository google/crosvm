// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use enumn::N;
use log::debug;

use crate::decoders::h264::backends::stateless::StatelessDecoderBackend;
use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::parser::Nalu;
use crate::decoders::h264::parser::NaluType;
use crate::decoders::h264::parser::Parser;
use crate::decoders::h264::parser::RefPicListModification;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::SliceType;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::Field;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::h264::picture::IsIdr;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::h264::picture::Reference;
use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::DynDecodedHandle;
use crate::decoders::Error as VideoDecoderError;
use crate::decoders::Result as VideoDecoderResult;
use crate::decoders::StatelessBackendError;
use crate::decoders::VideoDecoder;
use crate::decoders::VideoDecoderBackend;
use crate::Resolution;

/// The maximum number of pictures in the DPB, as per A.3.1, clause h)
const DPB_MAX_SIZE: usize = 16;

const ZIGZAG_8X8: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

const ZIGZAG_4X4: [usize; 16] = [0, 1, 4, 8, 5, 2, 3, 6, 9, 12, 13, 10, 7, 11, 14, 15];

#[derive(N)]
pub enum Profile {
    Baseline = 66,
    Main = 77,
    High = 100,
}

#[derive(N)]
enum Level {
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

#[derive(Copy, Clone, Debug)]
enum RefPicList {
    RefPicList0,
    RefPicList1,
}

#[derive(Copy, Clone, Debug)]
enum RefFrameListName {
    RefFrameList0ShortTerm,
    RefFrameList1ShortTerm,
    RefFrameListLongTerm,
}

#[derive(Copy, Clone, Debug)]
enum RefPicListName {
    P0,
    B0,
    B1,
}

pub struct PrevReferencePicInfo {
    frame_num: i32,
    has_mmco_5: bool,
    top_field_order_cnt: i32,
    pic_order_cnt_msb: i32,
    pic_order_cnt_lsb: i32,
    field: Field,
}

impl Default for PrevReferencePicInfo {
    fn default() -> Self {
        Self {
            frame_num: Default::default(),
            has_mmco_5: Default::default(),
            top_field_order_cnt: Default::default(),
            pic_order_cnt_msb: Default::default(),
            pic_order_cnt_lsb: Default::default(),
            field: Field::Frame,
        }
    }
}

#[derive(Default)]
pub struct PrevPicInfo {
    frame_num: i32,
    frame_num_offset: i32,
    has_mmco_5: bool,
}

#[derive(Default)]
pub struct CurrentPicInfo {
    max_frame_num: i32,
    max_pic_num: i32,
    max_long_term_frame_idx: i32,
}

#[cfg(test)]
struct Params<T> {
    ready_pics: Vec<T>,
}

#[cfg(test)]
impl<T> Params<T> {
    fn save_ready_pics(&mut self, ready_pics: Vec<T>) {
        self.ready_pics.extend(ready_pics);
    }
}

#[cfg(test)]
impl<T> Default for Params<T> {
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
    /// Still waiting for a SPS. Any incoming buffers are being queued in order.
    NonNegotiated { queued_buffers: Vec<(u64, Vec<u8>)> },
    /// Saw an SPS. Negotiation is possible until the next call to decode()
    Possible { queued_buffers: Vec<(u64, Vec<u8>)> },
    /// Processing the queued buffers.
    DrainingQueuedBuffers,
    /// Negotiated. Locks in the format until a new SPS is seen.
    Negotiated,
}

impl Default for NegotiationStatus {
    fn default() -> Self {
        Self::NonNegotiated {
            queued_buffers: Default::default(),
        }
    }
}

pub struct Decoder<T>
where
    T: DecodedHandle<CodecData = PictureData<<T as DecodedHandle>::BackendHandle>>
        + DynDecodedHandle,
{
    /// A parser to extract bitstream metadata
    parser: Parser,

    /// The current coded resolution
    coded_resolution: Resolution,

    /// Whether the decoder should block on decode operations.
    blocking_mode: BlockingMode,

    /// The backend used for hardware acceleration.
    backend: Box<dyn StatelessDecoderBackend<Handle = T>>,

    /// Keeps track of whether the decoded format has been negotiated with the
    /// backend.
    negotiation_status: NegotiationStatus,

    /// The decoded picture buffer
    dpb: Dpb<T>,

    /// Indicates an upper bound for the number of frames buffers, in the
    /// decoded picture buffer (DPB), that are required for storing frames,
    /// complementary field pairs, and non-paired fields before output. It is a
    /// requirement of bitstream conformance that the maximum number of frames,
    /// complementary field pairs, or non-paired fields that precede any frame,
    /// complementary field pair, or non-paired field in the coded video
    /// sequence in decoding order and follow it in output order shall be less
    /// than or equal to max_num_reorder_frames.
    max_num_reorder_frames: u32,

    /// A monotonically increasing counter used to tag pictures in display
    /// order
    current_display_order: u64,

    /// The current active SPS id.
    cur_sps_id: u8,
    /// The current active PPS id.
    cur_pps_id: u8,

    /// Cached variables from the previous reference picture.
    prev_ref_pic_info: PrevReferencePicInfo,
    /// Cached variables from the previous picture.
    prev_pic_info: PrevPicInfo,
    /// Cached variables from the current picture.
    curr_info: CurrentPicInfo,
    /// The current picture being worked on.
    cur_pic: Option<H264Picture<T::BackendHandle>>,
    /// A queue with the pictures that are ready to be sent to the DecoderSession.
    ready_queue: Vec<T>,

    /// A cached, non-reference first field that did not make it into the DPB
    /// because it was full even after bumping the smaller POC. This field will
    /// be cached until the second field is processed so they can be output
    /// together.
    last_field: Option<T>,

    /// Reference picture list for P slices. Retains the same meaning as in the
    /// specification. Points into the pictures stored in the DPB. Derived once
    /// per picture.
    ref_pic_list_p0: Vec<T>,
    /// Reference picture list 0 for B slices. Retains the same meaning as in
    /// the specification. Points into the pictures stored in the DPB. Derived
    /// once per picture.
    ref_pic_list_b0: Vec<T>,
    /// Reference picture list 1 for B slices. Retains the same meaning as in
    /// the specification. Points into the pictures stored in the DPB. Derived
    /// once per picture.
    ref_pic_list_b1: Vec<T>,
    /// Equivalent to refFrameList0ShortTerm in the spec. Used for building the
    /// references for P, SP and B slices in fields (8.2.4.2.2, 8.2.4.2.4).
    /// Derived once per field.
    ref_frame_list_0_short_term: Vec<T>,
    /// Equivalent to refFrameList1ShortTerm in the spec. Used for building the
    /// references for B slices in fields (8.2.4.2.4). Derived once per field.
    ref_frame_list_1_short_term: Vec<T>,
    /// Equivalent to refFrameList0LongTerm in the spec. Used for building the
    /// references for P, SP and B slices in fields (8.2.4.2.2, 8.2.4.2.4).
    /// Derived once per field.
    ref_frame_list_long_term: Vec<T>,

    /// Equivalent to RefPicList0 in the specification. Computed for every
    /// slice, points to the pictures in the DPB.
    ref_pic_list0: Vec<T>,
    /// Equivalent to RefPicList1 in the specification. Computed for every
    /// slice, points to the pictures in the DPB.
    ref_pic_list1: Vec<T>,

    #[cfg(test)]
    params: Params<T>,
}

impl<T> Decoder<T>
where
    T: DecodedHandle<CodecData = PictureData<<T as DecodedHandle>::BackendHandle>>
        + DynDecodedHandle
        + 'static,
{
    // Creates a new instance of the decoder.
    pub fn new(
        backend: Box<dyn StatelessDecoderBackend<Handle = T>>,
        blocking_mode: BlockingMode,
    ) -> Result<Self> {
        Ok(Self {
            backend,
            blocking_mode,
            parser: Default::default(),
            coded_resolution: Default::default(),
            negotiation_status: Default::default(),
            dpb: Default::default(),
            max_num_reorder_frames: Default::default(),
            current_display_order: Default::default(),
            cur_sps_id: Default::default(),
            cur_pps_id: Default::default(),
            prev_ref_pic_info: Default::default(),
            prev_pic_info: Default::default(),
            curr_info: Default::default(),
            cur_pic: Default::default(),
            last_field: Default::default(),
            ready_queue: Default::default(),
            ref_pic_list_p0: Default::default(),
            ref_pic_list_b0: Default::default(),
            ref_pic_list_b1: Default::default(),
            ref_frame_list_0_short_term: Default::default(),
            ref_frame_list_long_term: Default::default(),
            ref_frame_list_1_short_term: Default::default(),
            ref_pic_list0: Default::default(),
            ref_pic_list1: Default::default(),

            #[cfg(test)]
            params: Default::default(),
        })
    }

    pub fn max_dpb_frames(sps: &Sps) -> Result<usize> {
        let mut level = Level::n(sps.level_idc())
            .with_context(|| format!("Unsupported level {}", sps.level_idc()))?;
        let profile = Profile::n(sps.profile_idc())
            .with_context(|| format!("Unsupported profile {}", sps.profile_idc()))?;

        // A.3.1 and A.3.2: Level 1b for Baseline, Constrained Baseline and Main
        // profile if level_idc == 11 and constraint_set3_flag == 1
        if matches!(level, Level::L1_1)
            && (matches!(profile, Profile::Baseline) || matches!(profile, Profile::Main))
            && sps.constraint_set3_flag()
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

        let width_mb = sps.width() / 16;
        let height_mb = sps.height() / 16;

        let max_dpb_frames =
            std::cmp::min(max_dpb_mbs / (width_mb * height_mb), DPB_MAX_SIZE as u32) as usize;

        let mut max_dpb_frames = std::cmp::max(max_dpb_frames, sps.max_num_ref_frames() as usize);

        if sps.vui_parameters_present_flag() && sps.vui_parameters().bitstream_restriction_flag() {
            max_dpb_frames = std::cmp::max(
                1,
                sps.vui_parameters()
                    .max_dec_frame_buffering()
                    .try_into()
                    .unwrap(),
            );
        }

        Ok(max_dpb_frames)
    }

    fn negotiation_possible(
        sps: &Sps,
        dpb: &Dpb<T>,
        current_resolution: Resolution,
    ) -> Result<bool> {
        let max_dpb_frames = Self::max_dpb_frames(sps)?;

        let prev_max_dpb_frames = dpb.max_num_pics();
        let prev_interlaced = dpb.interlaced();
        let interlaced = !sps.frame_mbs_only_flag();

        let resolution = Resolution {
            width: sps.width(),
            height: sps.height(),
        };

        let needs_negotiation = current_resolution != resolution
            || prev_max_dpb_frames != max_dpb_frames
            || prev_interlaced != interlaced;

        Ok(needs_negotiation)
    }

    fn get_max_num_order_frames(sps: &Sps, max_dpb_frames: usize) -> u32 {
        let vui = sps.vui_parameters();
        let present = sps.vui_parameters_present_flag() && vui.bitstream_restriction_flag();

        if present {
            vui.max_num_reorder_frames()
        } else {
            let profile = sps.profile_idc();
            if (profile == 44
                || profile == 86
                || profile == 100
                || profile == 110
                || profile == 122
                || profile == 244)
                && sps.constraint_set3_flag()
            {
                0
            } else {
                max_dpb_frames as u32
            }
        }
    }

    fn process_sps(&mut self, nalu: &Nalu<impl AsRef<[u8]>>) -> Result<()> {
        let sps = self.parser.parse_sps(nalu)?;
        let negotiation_possible =
            Self::negotiation_possible(sps, &self.dpb, self.coded_resolution)?;

        if negotiation_possible {
            let max_dpb_frames = Self::max_dpb_frames(sps)?;
            let interlaced = !sps.frame_mbs_only_flag();
            let resolution = Resolution {
                width: sps.width(),
                height: sps.height(),
            };

            let max_num_reorder_frames = Self::get_max_num_order_frames(sps, max_dpb_frames);

            if max_num_reorder_frames > max_dpb_frames as u32 {
                self.max_num_reorder_frames = 0;
            } else {
                self.max_num_reorder_frames = max_num_reorder_frames;
            }

            self.drain()?;

            self.coded_resolution = resolution;

            self.dpb.set_max_num_pics(max_dpb_frames);
            self.dpb.set_interlaced(interlaced);
        }

        Ok(())
    }

    fn compute_pic_order_count(&mut self, pic: &mut H264Picture<T::BackendHandle>) -> Result<()> {
        let sps = self
            .parser
            .get_sps(self.cur_sps_id)
            .context("Invalid SPS while computing the value of POC for the current picture")?;

        match pic.pic_order_cnt_type {
            // Spec 8.2.1.1
            0 => {
                let prev_pic_order_cnt_msb;
                let prev_pic_order_cnt_lsb;

                if matches!(pic.is_idr, IsIdr::Yes { .. }) {
                    prev_pic_order_cnt_lsb = 0;
                    prev_pic_order_cnt_msb = 0;
                } else if self.prev_ref_pic_info.has_mmco_5 {
                    if !matches!(self.prev_ref_pic_info.field, Field::Bottom) {
                        prev_pic_order_cnt_msb = 0;
                        prev_pic_order_cnt_lsb = self.prev_ref_pic_info.top_field_order_cnt;
                    } else {
                        prev_pic_order_cnt_msb = 0;
                        prev_pic_order_cnt_lsb = 0;
                    }
                } else {
                    prev_pic_order_cnt_msb = self.prev_ref_pic_info.pic_order_cnt_msb;
                    prev_pic_order_cnt_lsb = self.prev_ref_pic_info.pic_order_cnt_lsb;
                }

                let max_pic_order_cnt_lsb = 1 << (sps.log2_max_pic_order_cnt_lsb_minus4() + 4);

                if (pic.pic_order_cnt_lsb < self.prev_ref_pic_info.pic_order_cnt_lsb)
                    && (prev_pic_order_cnt_lsb - pic.pic_order_cnt_lsb >= max_pic_order_cnt_lsb / 2)
                {
                    pic.pic_order_cnt_msb = prev_pic_order_cnt_msb + max_pic_order_cnt_lsb;
                } else if (pic.pic_order_cnt_lsb > prev_pic_order_cnt_lsb)
                    && (pic.pic_order_cnt_lsb - prev_pic_order_cnt_lsb > max_pic_order_cnt_lsb / 2)
                {
                    pic.pic_order_cnt_msb = prev_pic_order_cnt_msb - max_pic_order_cnt_lsb;
                } else {
                    pic.pic_order_cnt_msb = prev_pic_order_cnt_msb;
                }

                if !matches!(pic.field, Field::Bottom) {
                    pic.top_field_order_cnt = pic.pic_order_cnt_msb + pic.pic_order_cnt_lsb;
                }

                if !matches!(pic.field, Field::Top) {
                    if matches!(pic.field, Field::Frame) {
                        pic.bottom_field_order_cnt =
                            pic.top_field_order_cnt + pic.delta_pic_order_cnt_bottom;
                    } else {
                        pic.bottom_field_order_cnt = pic.pic_order_cnt_msb + pic.pic_order_cnt_lsb;
                    }
                }
            }

            1 => {
                if self.prev_pic_info.has_mmco_5 {
                    self.prev_pic_info.frame_num_offset = 0;
                }

                if matches!(pic.is_idr, IsIdr::Yes { .. }) {
                    pic.frame_num_offset = 0;
                } else if self.prev_pic_info.frame_num > pic.frame_num {
                    pic.frame_num_offset =
                        self.prev_pic_info.frame_num_offset + self.curr_info.max_frame_num as i32;
                } else {
                    pic.frame_num_offset = self.prev_pic_info.frame_num_offset;
                }

                let mut abs_frame_num = if sps.num_ref_frames_in_pic_order_cnt_cycle() != 0 {
                    pic.frame_num_offset + pic.frame_num as i32
                } else {
                    0
                };

                if pic.nal_ref_idc == 0 && abs_frame_num > 0 {
                    abs_frame_num -= 1;
                }

                let mut expected_pic_order_cnt = 0;

                if abs_frame_num > 0 {
                    if sps.num_ref_frames_in_pic_order_cnt_cycle() == 0 {
                        return Err(anyhow!("Invalid num_ref_frames_in_pic_order_cnt_cycle"));
                    }

                    let pic_order_cnt_cycle_cnt =
                        (abs_frame_num - 1) / sps.num_ref_frames_in_pic_order_cnt_cycle() as i32;
                    let frame_num_in_pic_order_cnt_cycle =
                        (abs_frame_num - 1) % sps.num_ref_frames_in_pic_order_cnt_cycle() as i32;
                    expected_pic_order_cnt =
                        pic_order_cnt_cycle_cnt * sps.expected_delta_per_pic_order_cnt_cycle();

                    assert!(frame_num_in_pic_order_cnt_cycle < 255);

                    for i in 0..sps.num_ref_frames_in_pic_order_cnt_cycle() {
                        expected_pic_order_cnt += sps.offset_for_ref_frame()[i as usize];
                    }
                }

                if pic.nal_ref_idc == 0 {
                    expected_pic_order_cnt += sps.offset_for_non_ref_pic();
                }

                if matches!(pic.field, Field::Frame) {
                    pic.top_field_order_cnt = expected_pic_order_cnt + pic.delta_pic_order_cnt0;

                    pic.bottom_field_order_cnt = pic.top_field_order_cnt
                        + sps.offset_for_top_to_bottom_field()
                        + pic.delta_pic_order_cnt1;
                } else if !matches!(pic.field, Field::Bottom) {
                    pic.top_field_order_cnt = expected_pic_order_cnt + pic.delta_pic_order_cnt0;
                } else {
                    pic.bottom_field_order_cnt = expected_pic_order_cnt
                        + sps.offset_for_top_to_bottom_field()
                        + pic.delta_pic_order_cnt0;
                }
            }

            2 => {
                // Spec 8.2.1.3
                if self.prev_pic_info.has_mmco_5 {
                    self.prev_pic_info.frame_num_offset = 0;
                }

                if matches!(pic.is_idr, IsIdr::Yes { .. }) {
                    pic.frame_num_offset = 0;
                } else if self.prev_pic_info.frame_num > pic.frame_num {
                    pic.frame_num_offset =
                        self.prev_pic_info.frame_num_offset + self.curr_info.max_frame_num as i32;
                } else {
                    pic.frame_num_offset = self.prev_pic_info.frame_num_offset;
                }

                let temp_pic_order_cnt;

                if matches!(pic.is_idr, IsIdr::Yes { .. }) {
                    temp_pic_order_cnt = 0;
                } else if pic.nal_ref_idc == 0 {
                    temp_pic_order_cnt = 2 * (pic.frame_num_offset + pic.frame_num as i32) - 1;
                } else {
                    temp_pic_order_cnt = 2 * (pic.frame_num_offset + pic.frame_num as i32);
                }

                if matches!(pic.field, Field::Frame) {
                    pic.top_field_order_cnt = temp_pic_order_cnt;
                    pic.bottom_field_order_cnt = temp_pic_order_cnt;
                } else if matches!(pic.field, Field::Bottom) {
                    pic.bottom_field_order_cnt = temp_pic_order_cnt;
                } else {
                    pic.top_field_order_cnt = temp_pic_order_cnt;
                }
            }

            _ => {
                return Err(anyhow!(
                    "Invalid pic_order_cnt_type: {}",
                    sps.pic_order_cnt_type()
                ))
            }
        }

        match pic.field {
            Field::Frame => {
                pic.pic_order_cnt =
                    std::cmp::min(pic.top_field_order_cnt, pic.bottom_field_order_cnt);
            }
            Field::Top => {
                pic.pic_order_cnt = pic.top_field_order_cnt;
            }
            Field::Bottom => {
                pic.pic_order_cnt = pic.bottom_field_order_cnt;
            }
        }

        Ok(())
    }

    fn update_pic_nums(
        &mut self,
        frame_num: i32,
        gap_picture: Option<&H264Picture<T::BackendHandle>>,
    ) -> Result<()> {
        let current_pic = if let Some(gap_picture) = gap_picture {
            gap_picture
        } else {
            self.cur_pic.as_ref().unwrap()
        };

        for mut pic in self.dpb.pictures_mut() {
            if !pic.is_ref() {
                continue;
            }

            if matches!(pic.reference(), Reference::LongTerm) {
                if matches!(current_pic.field, Field::Frame) {
                    pic.long_term_pic_num = pic.long_term_frame_idx;
                } else if current_pic.field == pic.field {
                    pic.long_term_pic_num = 2 * pic.long_term_frame_idx + 1;
                } else {
                    pic.long_term_pic_num = 2 * pic.long_term_frame_idx;
                }
            } else {
                if pic.frame_num > frame_num {
                    pic.frame_num_wrap = pic.frame_num - self.curr_info.max_frame_num;
                } else {
                    pic.frame_num_wrap = pic.frame_num;
                }

                if matches!(current_pic.field, Field::Frame) {
                    pic.pic_num = pic.frame_num_wrap;
                } else if pic.field == current_pic.field {
                    pic.pic_num = 2 * pic.frame_num_wrap + 1;
                } else {
                    pic.pic_num = 2 * pic.frame_num_wrap;
                }
            }
        }

        Ok(())
    }

    fn sort_pic_num_descending(pics: &mut [T]) {
        pics.sort_by_key(|h| std::cmp::Reverse(h.picture().pic_num));
    }

    fn sort_long_term_pic_num_ascending(pics: &mut [T]) {
        pics.sort_by_key(|h| h.picture().long_term_pic_num);
    }

    fn sort_frame_num_wrap_descending(pics: &mut [T]) {
        pics.sort_by_key(|h| std::cmp::Reverse(h.picture().frame_num_wrap));
    }

    fn sort_long_term_frame_idx_ascending(pics: &mut [T]) {
        pics.sort_by_key(|h| h.picture().long_term_frame_idx);
    }

    #[cfg(debug_assertions)]
    fn debug_ref_list_p(ref_pic_list: &[T], field_pic: bool) {
        debug!(
            "ref_list_p0: (ShortTerm|LongTerm, pic_num) {:?}",
            ref_pic_list
                .iter()
                .map(|h| {
                    let p = h.picture();
                    let reference = match p.reference() {
                        Reference::None => panic!("Not a reference."),
                        Reference::ShortTerm => "ShortTerm",
                        Reference::LongTerm => "LongTerm",
                    };

                    let field = if !p.is_second_field() {
                        "First field"
                    } else {
                        "Second field"
                    };

                    let field = format!("{}, {:?}", field, p.field);

                    let inner = match (field_pic, p.reference()) {
                        (false, _) => ("pic_num", p.pic_num, field),
                        (true, Reference::ShortTerm) => ("frame_num_wrap", p.frame_num_wrap, field),
                        (true, Reference::LongTerm) => {
                            ("long_term_frame_idx", p.long_term_frame_idx, field)
                        }

                        _ => panic!("Not a reference."),
                    };
                    (reference, inner)
                })
                .collect::<Vec<_>>()
        );
    }

    #[cfg(debug_assertions)]
    fn debug_ref_list_b(ref_pic_list: &[T], ref_pic_list_name: &str) {
        debug!(
            "{:?}: (ShortTerm|LongTerm, (POC|LongTermPicNum)) {:?}",
            ref_pic_list_name,
            ref_pic_list
                .iter()
                .map(|h| {
                    let p = h.picture();
                    let reference = match p.reference() {
                        Reference::None => panic!("Not a reference."),
                        Reference::ShortTerm => "ShortTerm",
                        Reference::LongTerm => "LongTerm",
                    };

                    let field = if !p.is_second_field() {
                        "First field"
                    } else {
                        "Second field"
                    };

                    let field = format!("{}, {:?}", field, p.field);

                    let inner = match p.reference() {
                        Reference::ShortTerm => ("POC", p.pic_order_cnt, field),
                        Reference::LongTerm => ("LongTermPicNum", p.long_term_pic_num, field),
                        _ => panic!("Not a reference!"),
                    };
                    (reference, inner)
                })
                .collect::<Vec<_>>()
        );
    }

    /// 8.2.4.2.1 Initialization process for the reference picture list for P
    /// and SP slices in frames
    fn init_ref_pic_list_p(&mut self) {
        self.ref_pic_list_p0.clear();

        let pics = &mut self.ref_pic_list_p0;

        self.dpb.get_short_term_refs(pics);
        pics.retain(|h| !h.picture().is_second_field());
        Self::sort_pic_num_descending(pics);

        let num_short_term_refs = pics.len();

        self.dpb.get_long_term_refs(pics);
        pics.retain(|h| !h.picture().is_second_field());
        Self::sort_long_term_pic_num_ascending(&mut pics[num_short_term_refs..]);

        #[cfg(debug_assertions)]
        Self::debug_ref_list_p(&self.ref_pic_list_p0, false);
    }

    /// 8.2.4.2.2 Initialization process for the reference picture list for P
    /// and SP slices in fields
    fn init_ref_field_pic_list_p(&mut self) {
        self.ref_pic_list_p0.clear();
        self.ref_frame_list_0_short_term.clear();
        self.ref_frame_list_long_term.clear();

        let pics = &mut self.ref_frame_list_0_short_term;

        self.dpb.get_short_term_refs(pics);
        Self::sort_frame_num_wrap_descending(pics);

        let pics = &mut self.ref_frame_list_long_term;
        self.dpb.get_long_term_refs(pics);
        Self::sort_long_term_pic_num_ascending(pics);

        // 8.2.4.2.5
        self.init_ref_field_pic_list(RefFrameListName::RefFrameList0ShortTerm, RefPicListName::P0);
        self.init_ref_field_pic_list(RefFrameListName::RefFrameListLongTerm, RefPicListName::P0);

        self.ref_frame_list_0_short_term.clear();
        self.ref_frame_list_long_term.clear();

        #[cfg(debug_assertions)]
        Self::debug_ref_list_p(&self.ref_pic_list_p0, true);
    }

    fn sort_poc_descending(pics: &mut [T]) {
        pics.sort_by_key(|h| std::cmp::Reverse(h.picture().pic_order_cnt));
    }

    fn sort_poc_ascending(pics: &mut [T]) {
        pics.sort_by_key(|h| h.picture().pic_order_cnt);
    }

    // When the reference picture list RefPicList1 has more than one entry
    // and RefPicList1 is identical to the reference picture list
    // RefPicList0, the first two entries RefPicList1[0] and RefPicList1[1]
    // are switched.
    fn swap_b1_if_needed(&mut self) {
        if self.ref_pic_list_b1.len() > 1
            && self.ref_pic_list_b0.len() == self.ref_pic_list_b1.len()
        {
            let mut equals = true;
            for (x1, x2) in self.ref_pic_list_b0.iter().zip(self.ref_pic_list_b1.iter()) {
                if !Rc::ptr_eq(x1.picture_container(), x2.picture_container()) {
                    equals = false;
                    break;
                }
            }

            if equals {
                self.ref_pic_list_b1.swap(0, 1);
            }
        }
    }

    // 8.2.4.2.3 Initialization process for reference picture lists for B slices
    // in frames
    fn init_ref_pic_list_b(&mut self) {
        self.ref_pic_list_b0.clear();
        self.ref_pic_list_b1.clear();

        let mut short_term_refs = vec![];
        let mut remaining = vec![];

        self.dpb.get_short_term_refs(&mut short_term_refs);
        short_term_refs.retain(|h| !h.picture().is_second_field());

        let cur_pic = self.cur_pic.as_ref().unwrap();

        // When pic_order_cnt_type is equal to 0, reference pictures that are
        // marked as "non-existing" as specified in clause 8.2.5.2 are not
        // included in either RefPicList0 or RefPicList1.
        if cur_pic.pic_order_cnt_type == 0 {
            short_term_refs.retain(|h| !h.picture().nonexisting);
        }

        // b0 contains three inner lists of pictures, i.e. [[0] [1] [2]]
        // [0]: short term pictures with POC < current, sorted by descending POC.
        // [1]: short term pictures with POC > current, sorted by ascending POC.
        // [2]: long term pictures sorted by ascending long_term_pic_num
        for handle in &short_term_refs {
            let pic = handle.picture();

            if pic.pic_order_cnt < cur_pic.pic_order_cnt {
                self.ref_pic_list_b0.push(handle.clone());
            } else {
                remaining.push(handle.clone());
            }
        }

        Self::sort_poc_descending(&mut self.ref_pic_list_b0);
        Self::sort_poc_ascending(&mut remaining);
        self.ref_pic_list_b0.append(&mut remaining);

        let mut long_term_refs = vec![];

        self.dpb.get_long_term_refs(&mut long_term_refs);
        long_term_refs.retain(|h| !h.picture().nonexisting);
        long_term_refs.retain(|h| !h.picture().is_second_field());
        Self::sort_long_term_pic_num_ascending(&mut long_term_refs);

        self.ref_pic_list_b0.extend(long_term_refs.clone());

        // b1 contains three inner lists of pictures, i.e. [[0] [1] [2]]
        // [0]: short term pictures with POC > current, sorted by ascending POC.
        // [1]: short term pictures with POC < current, sorted by descending POC.
        // [2]: long term pictures sorted by ascending long_term_pic_num
        for handle in &short_term_refs {
            let pic = handle.picture();

            if pic.pic_order_cnt > cur_pic.pic_order_cnt {
                self.ref_pic_list_b1.push(handle.clone());
            } else {
                remaining.push(handle.clone());
            }
        }

        Self::sort_poc_ascending(&mut self.ref_pic_list_b1);
        Self::sort_poc_descending(&mut remaining);

        self.ref_pic_list_b1.extend(remaining);
        self.ref_pic_list_b1.extend(long_term_refs);

        // When the reference picture list RefPicList1 has more than one entry
        // and RefPicList1 is identical to the reference picture list
        // RefPicList0, the first two entries RefPicList1[0] and RefPicList1[1]
        // are switched.
        self.swap_b1_if_needed();

        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(&self.ref_pic_list_b0, "ref_pic_list_b0");
        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(&self.ref_pic_list_b1, "ref_pic_list_b1");
    }

    /// 8.2.4.2.4 Initialization process for reference picture lists for B
    /// slices in fields
    fn init_ref_field_pic_list_b(&mut self) {
        self.ref_pic_list_b0.clear();
        self.ref_pic_list_b1.clear();
        self.ref_frame_list_0_short_term.clear();
        self.ref_frame_list_1_short_term.clear();
        self.ref_frame_list_long_term.clear();

        let mut short_term_refs = vec![];
        let mut remaining = vec![];

        self.dpb.get_short_term_refs(&mut short_term_refs);

        let cur_pic = self.cur_pic.as_ref().unwrap();

        // When pic_order_cnt_type is equal to 0, reference pictures that are
        // marked as "non-existing" as specified in clause 8.2.5.2 are not
        // included in either RefPicList0 or RefPicList1.
        if cur_pic.pic_order_cnt_type == 0 {
            short_term_refs.retain(|h| !h.picture().nonexisting);
        }

        // refFrameList0ShortTerm is comprised of two inner lists, [[0] [1]]
        // [0]: short term pictures with POC <= current, sorted by descending POC
        // [1]: short term pictures with POC > current, sorted by ascending POC
        // NOTE 3 – When the current field follows in decoding order a coded
        // field fldPrev with which together it forms a complementary reference
        // field pair, fldPrev is included into the list refFrameList0ShortTerm
        // using PicOrderCnt( fldPrev ) and the ordering method described in the
        // previous sentence is applied.
        for handle in &short_term_refs {
            let pic = handle.picture();

            if pic.pic_order_cnt <= cur_pic.pic_order_cnt {
                self.ref_frame_list_0_short_term.push(handle.clone());
            } else {
                remaining.push(handle.clone());
            }
        }

        Self::sort_poc_descending(&mut self.ref_frame_list_0_short_term);
        Self::sort_poc_ascending(&mut remaining);
        self.ref_frame_list_0_short_term.append(&mut remaining);

        // refFrameList1ShortTerm is comprised of two inner lists, [[0] [1]]
        // [0]: short term pictures with POC > current, sorted by ascending POC
        // [1]: short term pictures with POC <= current, sorted by descending POC
        // NOTE 4 – When the current field follows in decoding order a coded
        // field fldPrev with which together it forms a complementary reference
        // field pair, fldPrev is included into the list refFrameList1ShortTerm
        // using PicOrderCnt( fldPrev ) and the ordering method described in the
        // previous sentence is applied.

        for handle in &short_term_refs {
            let pic = handle.picture();

            if pic.pic_order_cnt > cur_pic.pic_order_cnt {
                self.ref_frame_list_1_short_term.push(handle.clone());
            } else {
                remaining.push(handle.clone());
            }
        }

        Self::sort_poc_ascending(&mut self.ref_frame_list_1_short_term);
        Self::sort_poc_descending(&mut remaining);
        self.ref_frame_list_1_short_term.append(&mut remaining);

        // refFrameListLongTerm: long term pictures sorted by ascending
        // LongTermFrameIdx.
        // NOTE 5 – When the current picture is the second field of a
        // complementary field pair and the first field of the complementary
        // field pair is marked as "used for long-term reference", the first
        // field is included into the list refFrameListLongTerm. A reference
        // entry in which only one field is marked as "used for long-term
        // reference" is included into the list refFrameListLongTerm
        self.dpb
            .get_long_term_refs(&mut self.ref_frame_list_long_term);

        self.ref_frame_list_long_term
            .retain(|h| !h.picture().nonexisting);

        Self::sort_long_term_frame_idx_ascending(&mut self.ref_frame_list_long_term);

        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(
            &self.ref_frame_list_0_short_term,
            "ref_frame_list_0_short_term",
        );
        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(
            &self.ref_frame_list_1_short_term,
            "ref_frame_list_1_short_term",
        );
        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(&self.ref_frame_list_long_term, "ref_frame_list_long_term");

        // 8.2.4.2.5
        self.init_ref_field_pic_list(RefFrameListName::RefFrameList0ShortTerm, RefPicListName::B0);
        self.init_ref_field_pic_list(RefFrameListName::RefFrameListLongTerm, RefPicListName::B0);

        self.init_ref_field_pic_list(RefFrameListName::RefFrameList1ShortTerm, RefPicListName::B1);
        self.init_ref_field_pic_list(RefFrameListName::RefFrameListLongTerm, RefPicListName::B1);

        // When the reference picture list RefPicList1 has more than one entry
        // and RefPicList1 is identical to the reference picture list
        // RefPicList0, the first two entries RefPicList1[0] and RefPicList1[1]
        // are switched.
        self.swap_b1_if_needed();

        self.ref_frame_list_0_short_term.clear();
        self.ref_frame_list_1_short_term.clear();
        self.ref_frame_list_long_term.clear();

        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(&self.ref_pic_list_b0, "ref_pic_list_b0");
        #[cfg(debug_assertions)]
        Self::debug_ref_list_b(&self.ref_pic_list_b1, "ref_pic_list_b1");
    }

    /// Copies from refFrameListXShortTerm and refFrameListLongTerm into
    /// RefPicListX as per 8.2.4.2.5. Used when building the reference list for
    /// fields in interlaced decoding.
    fn init_ref_field_pic_list(
        &mut self,
        ref_frame_list_name: RefFrameListName,
        ref_pic_list_name: RefPicListName,
    ) {
        let ref_pic_list_x = match ref_pic_list_name {
            RefPicListName::P0 => &mut self.ref_pic_list_p0,
            RefPicListName::B0 => &mut self.ref_pic_list_b0,
            RefPicListName::B1 => &mut self.ref_pic_list_b1,
        };

        match ref_frame_list_name {
            RefFrameListName::RefFrameList0ShortTerm | RefFrameListName::RefFrameList1ShortTerm => {
                let short_term_list = match ref_frame_list_name {
                    RefFrameListName::RefFrameList0ShortTerm => {
                        &mut self.ref_frame_list_0_short_term
                    }
                    RefFrameListName::RefFrameList1ShortTerm => {
                        &mut self.ref_frame_list_1_short_term
                    }
                    RefFrameListName::RefFrameListLongTerm => {
                        panic!("Invalid value for RefFrameListName")
                    }
                };

                // When one field of a reference frame was not decoded or is
                // not marked as "used for short-term reference", the
                // missing field is ignored and instead the next available
                // stored reference field of the chosen parity from the
                // ordered list of frames refFrameListXShortTerm is inserted
                // into RefPicListX.
                short_term_list.retain(|h| {
                    let p = h.picture();
                    let skip = p.nonexisting || !matches!(p.reference(), Reference::ShortTerm);
                    !skip
                });

                let mut field = self.cur_pic.as_ref().unwrap().field;
                while let Some(position) = short_term_list.iter().position(|h| {
                    let p = h.picture();
                    let found = p.field == field;

                    if found {
                        field = field.opposite().unwrap();
                    }

                    found
                }) {
                    let pic = short_term_list.remove(position);
                    ref_pic_list_x.push(pic);
                }

                ref_pic_list_x.append(short_term_list);
            }

            RefFrameListName::RefFrameListLongTerm => {
                let long_term_list = &mut self.ref_frame_list_long_term;

                // When one field of a reference frame was not decoded or is
                // not marked as "used for long-term reference", the missing
                // field is ignored and instead the next available stored
                // reference field of the chosen parity from the ordered list
                // of frames refFrameListLongTerm is inserted into RefPicListX.
                long_term_list.retain(|h| {
                    let p = h.picture();
                    let skip = p.nonexisting || !matches!(p.reference(), Reference::LongTerm);
                    !skip
                });

                let mut field = self.cur_pic.as_ref().unwrap().field;
                while let Some(position) = long_term_list.iter().position(|h| {
                    let p = h.picture();
                    let found = p.field == field;

                    if found {
                        field = field.opposite().unwrap();
                    }

                    found
                }) {
                    let pic = long_term_list.remove(position);
                    ref_pic_list_x.push(pic);
                }

                ref_pic_list_x.append(long_term_list);
            }
        }
    }

    fn init_ref_pic_lists(&mut self) {
        let num_refs = self
            .dpb
            .pictures()
            .filter(|p| p.is_ref() && !p.nonexisting)
            .count();

        // 8.2.4.2.1 ~ 8.2.4.2.4: When this process is invoked, there shall be
        // at least one reference frame or complementary reference field pair
        // that is currently marked as "used for reference" (i.e., as "used for
        // short-term reference" or "used for long-term reference") and is not
        // marked as "non-existing".
        if num_refs == 0 {
            self.clear_ref_pic_lists();
            return;
        }

        if matches!(self.cur_pic.as_ref().unwrap().field, Field::Frame) {
            self.init_ref_pic_list_p();
            self.init_ref_pic_list_b();
        } else {
            self.init_ref_field_pic_list_p();
            self.init_ref_field_pic_list_b();
        }
    }

    fn sliding_window_marking(&mut self, pic: &mut H264Picture<T::BackendHandle>) -> Result<()> {
        // If the current picture is a coded field that is the second field in
        // decoding order of a complementary reference field pair, and the first
        // field has been marked as "used for short-term reference", the current
        // picture and the complementary reference field pair are also marked as
        // "used for short-term reference".
        if pic.is_second_field()
            && matches!(
                pic.other_field_unchecked().borrow().reference(),
                Reference::ShortTerm
            )
        {
            pic.set_reference(Reference::ShortTerm, false);
            return Ok(());
        }

        let sps = self
            .parser
            .get_sps(self.cur_sps_id)
            .context("Invalid SPS during the sliding window marking process")?;

        let mut num_ref_pics = self.dpb.num_ref_frames();
        let max_num_ref_frames =
            usize::try_from(std::cmp::max(1, sps.max_num_ref_frames())).unwrap();

        if num_ref_pics < max_num_ref_frames {
            return Ok(());
        }

        /* 8.2.5.3 */
        while num_ref_pics >= max_num_ref_frames {
            let to_unmark = self
                .dpb
                .find_short_term_lowest_frame_num_wrap()
                .context("Could not find a ShortTerm picture to unmark in the DPB")?;

            to_unmark.picture_mut().set_reference(Reference::None, true);
            num_ref_pics -= 1;
        }

        Ok(())
    }

    fn mmco_op_1(&self, pic: &H264Picture<T::BackendHandle>, marking: usize) -> Result<()> {
        let marking = &pic.ref_pic_marking.inner()[marking];
        let pic_num_x =
            pic.pic_num - (i32::try_from(marking.difference_of_pic_nums_minus1()).unwrap() + 1);

        log::debug!("MMCO op 1 for pic_num_x {}", pic_num_x);
        log::trace!("Dpb state before MMCO=1: {:#?}", self.dpb);

        let to_mark = self
            .dpb
            .find_short_term_with_pic_num(pic_num_x)
            .context("Could not find a ShortTerm picture to mark in the DPB")?;

        to_mark
            .picture_mut()
            .set_reference(Reference::None, matches!(pic.field, Field::Frame));

        Ok(())
    }

    fn mmco_op_2(&self, pic: &H264Picture<T::BackendHandle>, marking: usize) -> Result<()> {
        let marking = &pic.ref_pic_marking.inner()[marking];

        log::debug!(
            "MMCO op 2 for long_term_pic_num {}",
            marking.long_term_pic_num()
        );

        log::trace!("Dpb state before MMCO=2: {:#?}", self.dpb);

        let to_mark = self
            .dpb
            .find_long_term_with_long_term_pic_num(
                i32::try_from(marking.long_term_pic_num()).unwrap(),
            )
            .context("Could not find a LongTerm picture to mark in the DPB")?;

        to_mark
            .picture_mut()
            .set_reference(Reference::None, matches!(pic.field, Field::Frame));

        Ok(())
    }

    fn mmco_op_3(&self, pic: &H264Picture<T::BackendHandle>, marking: usize) -> Result<()> {
        let marking = &pic.ref_pic_marking.inner()[marking];
        let pic_num_x =
            pic.pic_num - (i32::try_from(marking.difference_of_pic_nums_minus1()).unwrap() + 1);

        log::debug!("MMCO op 3 for pic_num_x {}", pic_num_x);
        log::trace!("Dpb state before MMCO=3: {:#?}", self.dpb);

        let to_mark_as_long = self
            .dpb
            .find_short_term_with_pic_num(pic_num_x)
            .context("Could not find a ShortTerm picture to mark in the DPB")?;

        if !matches!(to_mark_as_long.picture().reference(), Reference::ShortTerm) {
            return Err(anyhow!(
                "A ShortTerm picture was expected to be marked for MMCO=3"
            ));
        }

        if to_mark_as_long.picture().nonexisting {
            return Err(anyhow!(
                "Picture cannot be marked as nonexisting for MMCO=3"
            ));
        }

        let long_term_frame_idx = i32::try_from(marking.long_term_frame_idx()).unwrap();

        for handle in self.dpb.handles() {
            let mut dpb_pic = handle.picture_mut();

            let long_already_assigned = matches!(dpb_pic.reference(), Reference::LongTerm)
                && dpb_pic.long_term_frame_idx == long_term_frame_idx;

            if long_already_assigned {
                let is_frame = matches!(dpb_pic.field, Field::Frame);

                let is_complementary_field_pair = dpb_pic.other_field().is_some()
                    && matches!(
                        dpb_pic.other_field_unchecked().borrow().reference(),
                        Reference::LongTerm
                    )
                    && dpb_pic.other_field_unchecked().borrow().long_term_frame_idx
                        == long_term_frame_idx;

                // When LongTermFrameIdx equal to
                // long_term_frame_idx is already assigned to a
                // long-term reference frame or a long-term
                // complementary reference field pair, that frame or
                // complementary field pair and both of its fields
                // are marked as "unused for reference"
                if is_frame || is_complementary_field_pair {
                    dpb_pic.set_reference(Reference::None, true);
                    break;
                }

                // When LongTermFrameIdx is already assigned to a
                // reference field, and that reference field is not
                // part of a complementary field pair that includes
                // the picture specified by picNumX, that field is
                // marked as "unused for reference".
                let reference_field_is_not_part_of_pic_x = if dpb_pic.other_field().is_none() {
                    true
                } else {
                    let fields_do_not_reference_each_other =
                        !H264Picture::same(
                            &dpb_pic.other_field_unchecked(),
                            to_mark_as_long.picture_container(),
                        ) && (to_mark_as_long.picture().other_field().is_none()
                            || !H264Picture::same(
                                &to_mark_as_long.picture().other_field_unchecked(),
                                handle.picture_container(),
                            ));

                    fields_do_not_reference_each_other
                };

                if reference_field_is_not_part_of_pic_x {
                    dpb_pic.set_reference(Reference::None, false);
                    break;
                }
            }
        }

        let is_frame = matches!(pic.field, Field::Frame);
        to_mark_as_long
            .picture_mut()
            .set_reference(Reference::LongTerm, is_frame);
        to_mark_as_long.picture_mut().long_term_frame_idx = long_term_frame_idx;

        if let Some(other_field) = to_mark_as_long.picture().other_field() {
            let other_field = other_field.upgrade().unwrap();
            let mut other_field = other_field.borrow_mut();
            if matches!(other_field.reference(), Reference::LongTerm) {
                other_field.long_term_frame_idx = long_term_frame_idx;

                log::debug!(
                    "Assigned long_term_frame_idx {} to other_field {:#?}",
                    long_term_frame_idx,
                    &other_field
                );
            }
        }

        Ok(())
    }

    fn mmco_op_4(&mut self, pic: &H264Picture<T::BackendHandle>, marking: usize) -> Result<()> {
        let marking = &pic.ref_pic_marking.inner()[marking];

        self.curr_info.max_long_term_frame_idx = marking.max_long_term_frame_idx_plus1() - 1;

        log::debug!(
            "MMCO op 4, max_long_term_frame_idx: {}",
            self.curr_info.max_long_term_frame_idx
        );

        log::trace!("Dpb state before MMCO=4: {:#?}", self.dpb);

        for mut dpb_pic in self.dpb.pictures_mut() {
            if matches!(dpb_pic.reference(), Reference::LongTerm)
                && dpb_pic.long_term_frame_idx > self.curr_info.max_long_term_frame_idx
            {
                dpb_pic.set_reference(Reference::None, false);
            }
        }

        Ok(())
    }

    fn mmco_op_5(&mut self, pic: &mut H264Picture<T::BackendHandle>) -> Result<()> {
        log::debug!("MMCO op 5, marking all pictures in the DPB as unused for reference");
        log::trace!("Dpb state before MMCO=5: {:#?}", self.dpb);

        self.dpb.mark_all_as_unused_for_ref();

        pic.has_mmco_5 = true;

        // A picture including a memory_management_control_operation equal to 5
        // shall have frame_num constraints as described above and, after the
        // decoding of the current picture and the processing of the memory
        // management control operations, the picture shall be inferred to have
        // had frame_num equal to 0 for all subsequent use in the decoding
        // process, except as specified in clause 7.4.1.2.4.
        pic.frame_num = 0;

        self.curr_info.max_long_term_frame_idx = -1;

        // When the current picture includes a
        // memory_management_control_operation equal to 5, after the decoding of
        // the current picture, tempPicOrderCnt is set equal to PicOrderCnt(
        // CurrPic ), TopFieldOrderCnt of the current picture (if any) is set
        // equal to TopFieldOrderCnt − tempPicOrderCnt, and BottomFieldOrderCnt
        // of the current picture (if any) is set equal to BottomFieldOrderCnt −
        // tempPicOrderCnt
        match pic.field {
            Field::Top => {
                pic.top_field_order_cnt = 0;
                pic.pic_order_cnt = 0;
            }
            Field::Bottom => {
                pic.bottom_field_order_cnt = 0;
                pic.pic_order_cnt = 0;
            }
            Field::Frame => {
                pic.top_field_order_cnt -= pic.pic_order_cnt;
                pic.bottom_field_order_cnt -= pic.pic_order_cnt;
                pic.pic_order_cnt =
                    std::cmp::min(pic.top_field_order_cnt, pic.bottom_field_order_cnt);
            }
        }

        Ok(())
    }

    fn mmco_op_6(&self, pic: &mut H264Picture<T::BackendHandle>, marking: usize) -> Result<()> {
        let marking = &pic.ref_pic_marking.inner()[marking];
        let long_term_frame_idx = i32::try_from(marking.long_term_frame_idx()).unwrap();

        log::debug!("MMCO op 6, long_term_frame_idx: {}", long_term_frame_idx);
        log::trace!("Dpb state before MMCO=6: {:#?}", self.dpb);

        for handle in self.dpb.handles() {
            let mut dpb_pic = handle.picture_mut();

            // When a variable LongTermFrameIdx equal to long_term_frame_idx is
            // already assigned to a long-term reference frame or a long-term
            // complementary reference field pair, that frame or complementary
            // field pair and both of its fields are marked as "unused for
            // reference". When LongTermFrameIdx is already assigned to a
            // reference field, and that reference field is not part of a
            // complementary field pair that includes the current picture, that
            // field is marked as "unused for reference".
            if matches!(dpb_pic.reference(), Reference::LongTerm)
                && dpb_pic.long_term_frame_idx == long_term_frame_idx
            {
                let is_frame = matches!(dpb_pic.field, Field::Frame);

                let is_complementary_ref_field_pair = dpb_pic.other_field().is_some()
                    && matches!(
                        dpb_pic.other_field_unchecked().borrow().reference(),
                        Reference::LongTerm
                    )
                    && dpb_pic.other_field_unchecked().borrow().long_term_frame_idx
                        == long_term_frame_idx;

                dpb_pic.set_reference(Reference::None, is_frame || is_complementary_ref_field_pair);

                break;
            }
        }

        let is_frame = matches!(pic.field, Field::Frame);

        let is_second_ref_field = pic.is_second_field()
            && matches!(
                pic.other_field_unchecked().borrow().reference(),
                Reference::LongTerm
            );

        pic.set_reference(Reference::LongTerm, is_frame || is_second_ref_field);
        pic.long_term_frame_idx = long_term_frame_idx;

        if is_second_ref_field {
            pic.other_field_unchecked().borrow_mut().long_term_frame_idx = long_term_frame_idx;
        }

        Ok(())
    }

    fn handle_memory_management_ops(
        &mut self,
        pic: &mut H264Picture<T::BackendHandle>,
    ) -> Result<()> {
        let markings = pic.ref_pic_marking.clone();

        for (i, marking) in markings.inner().iter().enumerate() {
            match marking.memory_management_control_operation() {
                0 => break,
                1 => self.mmco_op_1(pic, i)?,
                2 => self.mmco_op_2(pic, i)?,
                3 => self.mmco_op_3(pic, i)?,
                4 => self.mmco_op_4(pic, i)?,
                5 => self.mmco_op_5(pic)?,
                6 => self.mmco_op_6(pic, i)?,
                other => panic!("Unknown MMCO={}", other),
            }
        }

        Ok(())
    }

    /// Store some variables related to the previous reference picture. These
    /// will be used in the decoding of future pictures.
    fn fill_prev_ref_info(&mut self, pic: &H264Picture<T::BackendHandle>) {
        let prev = &mut self.prev_ref_pic_info;

        prev.has_mmco_5 = pic.has_mmco_5;
        prev.top_field_order_cnt = pic.top_field_order_cnt;
        prev.pic_order_cnt_msb = pic.pic_order_cnt_msb;
        prev.pic_order_cnt_lsb = pic.pic_order_cnt_lsb;
        prev.field = pic.field;
        prev.frame_num = pic.frame_num;
    }

    /// Store some variables related to the previous picture. These will be used
    /// in the decoding of future pictures.
    fn fill_prev_info(&mut self, pic: &H264Picture<T::BackendHandle>) {
        let prev = &mut self.prev_pic_info;

        prev.frame_num = pic.frame_num;
        prev.has_mmco_5 = pic.has_mmco_5;
        prev.frame_num_offset = pic.frame_num_offset;
    }

    fn reference_pic_marking(&mut self, pic: &mut H264Picture<T::BackendHandle>) -> Result<()> {
        /* 8.2.5.1 */
        if matches!(pic.is_idr, IsIdr::Yes { .. }) {
            self.dpb.mark_all_as_unused_for_ref();

            if pic.ref_pic_marking.long_term_reference_flag() {
                pic.set_reference(Reference::LongTerm, false);
                pic.long_term_frame_idx = 0;
                self.curr_info.max_long_term_frame_idx = 0;
            } else {
                pic.set_reference(Reference::ShortTerm, false);
                self.curr_info.max_long_term_frame_idx = -1;
            }

            return Ok(());
        }

        if pic.ref_pic_marking.adaptive_ref_pic_marking_mode_flag() {
            self.handle_memory_management_ops(pic)?;
        } else {
            self.sliding_window_marking(pic)?;
        }

        Ok(())
    }

    fn add_to_dpb(&mut self, handle: T) -> Result<()> {
        if !self.dpb.interlaced() {
            assert!(self.last_field.is_none());

            self.dpb.store_picture(handle)?;
        } else {
            if self.last_field.is_some()
                && handle.picture().other_field().is_some()
                && H264Picture::same(
                    &handle.picture().other_field_unchecked(),
                    self.last_field.as_ref().unwrap().picture_container(),
                )
            {
                // If we have a cached field for this picture, we must combine
                // them before insertion.
                let last_field = self.last_field.take().unwrap();
                self.dpb.store_picture(last_field)?;
            }

            self.dpb.store_picture(handle)?;
        }

        Ok(())
    }

    /// Adds picture to the ready queue if it could not be added to the DPB.
    fn add_to_ready_queue(&mut self, handle: T) -> Result<()> {
        if matches!(handle.picture().field, Field::Frame) {
            assert!(self.last_field.is_none());

            self.ready_queue.push(handle);
        } else if self.last_field.is_none() {
            assert!(!handle.picture().is_second_field());

            // Cache the field, wait for its pair.
            self.last_field = Some(handle);
        } else if !handle.picture().is_second_field()
            || handle.picture().other_field().is_none()
            || !H264Picture::same(
                &handle.picture().other_field_unchecked(),
                self.last_field.as_ref().unwrap().picture_container(),
            )
        {
            // Somehow, the last field is not paired with the current field.
            self.last_field = None;
        } else {
            let to_output = self.last_field.take().unwrap();

            to_output
                .picture_mut()
                .set_second_field_to(Rc::clone(handle.picture_container()));

            self.ready_queue.push(to_output);
        }

        Ok(())
    }

    fn finish_picture(&mut self, handle: T) -> Result<()> {
        debug!("Finishing picture POC {:?}", handle.picture().pic_order_cnt);

        if matches!(
            handle.picture().reference(),
            Reference::ShortTerm | Reference::LongTerm
        ) {
            self.reference_pic_marking(&mut handle.picture_mut())?;
            self.fill_prev_ref_info(&handle.picture());
        }

        self.clear_ref_pic_lists();
        self.fill_prev_info(&handle.picture());

        self.dpb.remove_unused();

        if handle.picture().has_mmco_5 {
            // C.4.5.3 "Bumping process"
            // The bumping process is invoked in the following cases:
            // Clause 3:
            // The current picture has memory_management_control_operation equal
            // to 5, as specified in clause C.4.4.
            self.drain()?;
        }

        // Bump the DPB as per C.4.5.3 to cover clauses 1, 4, 5 and 6.
        let bumped = self.bump_as_needed(&handle.picture());
        self.ready_queue.extend(bumped);
        // C.4.5.1, C.4.5.2
        // If the current decoded picture is the second field of a complementary
        // reference field pair, add to DPB.
        // C.4.5.1
        // For a reference decoded picture, the "bumping" process is invoked
        // repeatedly until there is an empty frame buffer, by which point it is
        // added to the DPB. Notice that Dpb::needs_bumping already accounts for
        // this.
        // C.4.5.2
        // For a non-reference decoded picture, if there is empty frame buffer
        // after bumping the smaller POC, add to DPB. Otherwise, add it to the
        // ready queue.
        if handle.picture().is_second_field_of_complementary_ref_pair()
            || handle.picture().is_ref()
            || self.dpb.has_empty_frame_buffer()
        {
            if self.dpb.interlaced() && matches!(handle.picture().field, Field::Frame) {
                // Split the Frame into two complementary fields so reference
                // marking is easier. This is inspired by the GStreamer implementation.
                let other_field = H264Picture::split_frame(Rc::clone(handle.picture_container()));

                self.backend.new_split_picture(
                    Rc::clone(handle.picture_container()),
                    Rc::clone(&other_field),
                )?;

                let other_field = self.backend.new_handle(other_field)?;

                self.add_to_dpb(handle.clone())?;
                self.add_to_dpb(other_field)?;
            } else {
                self.add_to_dpb(handle.clone())?;
            }
        } else {
            self.add_to_ready_queue(handle.clone())?;
            self.ready_queue.sort_by_key(|h| h.picture().pic_order_cnt);
        }

        Ok(())
    }

    fn handle_frame_num_gap(&mut self, frame_num: i32, timestamp: u64) -> Result<()> {
        if self.dpb.handles().len() == 0 {
            return Ok(());
        }

        debug!("frame_num gap detected.");

        let sps = self
            .parser
            .get_sps(self.cur_sps_id)
            .context("Invalid SPS while handling a frame_num gap")?;

        if !sps.gaps_in_frame_num_value_allowed_flag() {
            return Err(anyhow!("Invalid frame_num: {}", frame_num));
        }

        let mut unused_short_term_frame_num =
            (self.prev_ref_pic_info.frame_num + 1) % self.curr_info.max_frame_num;
        while unused_short_term_frame_num != frame_num {
            let mut pic = H264Picture::new_non_existing(frame_num, timestamp);
            self.compute_pic_order_count(&mut pic)?;

            self.update_pic_nums(unused_short_term_frame_num, Some(&pic))?;

            self.sliding_window_marking(&mut pic)?;

            self.dpb.remove_unused();
            self.bump_as_needed(&pic);

            let pic = Rc::new(RefCell::new(pic));

            if self.dpb.interlaced() {
                let other_field = H264Picture::split_frame(Rc::clone(&pic));
                let other_field = self.backend.new_handle(other_field)?;
                let handle = self.backend.new_handle(pic)?;

                self.add_to_dpb(handle)?;
                self.add_to_dpb(other_field)?;
            } else {
                let handle = self.backend.new_handle(pic)?;
                self.add_to_dpb(handle)?;
            }

            unused_short_term_frame_num += 1;
            unused_short_term_frame_num %= self.curr_info.max_frame_num;
        }

        Ok(())
    }

    /// Init the current picture being decoded.
    fn init_current_pic(
        &mut self,
        slice: &Slice<&dyn AsRef<[u8]>>,
        first_field: Option<T>,
        timestamp: u64,
    ) -> Result<()> {
        let pps = self
            .parser
            .get_pps(slice.header().pic_parameter_set_id())
            .context("Invalid SPS in init_current_pic")?;

        let sps = self
            .parser
            .get_sps(pps.seq_parameter_set_id())
            .context("Invalid PPS in init_current_pic")?;

        let mut pic = H264Picture::new_from_slice(slice, sps, timestamp);

        if let Some(first_field) = first_field {
            pic.set_first_field_to(Rc::clone(first_field.picture_container()));
        }

        self.compute_pic_order_count(&mut pic)?;
        self.cur_pic = Some(pic);

        Ok(())
    }

    /// Bumps the DPB if needed. DPB bumping is described on C.4.5.3.
    fn bump_as_needed(&mut self, current_pic: &H264Picture<T::BackendHandle>) -> Vec<T> {
        let mut pics = vec![];
        while self.dpb.needs_bumping(current_pic)
            && self.dpb.handles().len() >= self.max_num_reorder_frames as usize
        {
            match self.dpb.bump(false) {
                Some(pic) => pics.push(pic),
                None => return pics,
            }
        }

        pics
    }

    fn clear_ref_pic_lists(&mut self) {
        self.ref_pic_list_p0.clear();
        self.ref_pic_list_b0.clear();
        self.ref_pic_list_b1.clear();

        self.ref_pic_list0.clear();
        self.ref_pic_list1.clear();
    }

    /// Get the DecodedFrameHandle s for the pictures in the ready queue.
    fn get_ready_frames(&mut self) -> Vec<T> {
        for h in &mut self.ready_queue {
            if DecodedHandle::display_order(h).is_none() {
                let order = self.current_display_order;
                h.set_display_order(order);
                self.current_display_order += 1;
            }
        }

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

    /// Drain the decoder, processing all pending frames.
    fn drain(&mut self) -> Result<()> {
        debug!("Draining the decoder.");
        self.backend.poll(BlockingMode::Blocking)?;

        let pics = self.dpb.drain();

        // At this point all pictures will have been decoded, as we don't buffer
        // decode requests, but instead process them immediately, so refs will
        // not be needed.
        self.clear_ref_pic_lists();

        // Pics in the DPB have undergone `finish_picture` already or are
        // nonexisting frames, we can just mark them as ready.
        self.ready_queue.extend(pics);

        self.dpb.clear();

        self.last_field = None;

        Ok(())
    }

    /// Find the first field for the picture started by `slice`, if any.
    fn find_first_field(&mut self, slice: &Slice<impl AsRef<[u8]>>) -> Result<Option<T>> {
        let mut prev_field = None;

        if self.dpb.interlaced() {
            if self.last_field.is_some() {
                prev_field = self.last_field.clone();
            } else if self.dpb.handles().len() > 0 {
                // Use the last entry in the DPB
                let last_handle = self.dpb.handles().last().unwrap();
                let prev_pic = last_handle.picture();

                if !matches!(prev_pic.field, Field::Frame) && prev_pic.other_field().is_none() {
                    // Still waiting for the second field
                    prev_field = Some(last_handle.clone());
                }
            }
        }

        if !slice.header().field_pic_flag() && prev_field.is_some() {
            let field = prev_field.as_ref().unwrap().picture().field;
            return Err(anyhow!(
                "Expecting complementary field {:?}, got {:?}",
                field.opposite(),
                field
            ));
        }

        if prev_field.is_none() {
            return Ok(None);
        }

        let prev_field_pic = prev_field.as_ref().unwrap().picture();

        if prev_field_pic.frame_num != i32::from(slice.header().frame_num()) {
            return Err(anyhow!(
                "The previous field differs in frame_num value wrt. the current field. {:?} vs {:?}",
                prev_field_pic.frame_num,
                slice.header().frame_num()
            ));
        } else {
            let cur_field = if slice.header().bottom_field_flag() {
                Field::Bottom
            } else {
                Field::Top
            };

            if cur_field == prev_field_pic.field {
                let field = prev_field_pic.field;
                return Err(anyhow!(
                    "Expecting complementary field {:?}, got {:?}",
                    field.opposite(),
                    field
                ));
            }
        }

        Ok(Some(prev_field.as_ref().unwrap().clone()))
    }

    /// Handle a picture. Called only once. Uses an heuristic to determine when
    /// a new picture starts in the slice NALUs.
    fn handle_picture(&mut self, timestamp: u64, slice: &Slice<&dyn AsRef<[u8]>>) -> Result<()> {
        let nalu_hdr = slice.nalu().header();

        if nalu_hdr.idr_pic_flag() {
            self.prev_ref_pic_info.frame_num = 0;
        }

        let hdr = slice.header();
        let frame_num = i32::from(hdr.frame_num());

        self.cur_pps_id = hdr.pic_parameter_set_id();

        let pps = self
            .parser
            .get_pps(self.cur_pps_id)
            .context("Invalid PPS in handle_picture")?;

        self.cur_sps_id = pps.seq_parameter_set_id();

        let sps = self
            .parser
            .get_sps(self.cur_sps_id)
            .context("Invalid SPS in handle_picture")?;

        self.curr_info.max_frame_num = 1 << (sps.log2_max_frame_num_minus4() + 4);

        if frame_num != self.prev_ref_pic_info.frame_num
            && frame_num != (self.prev_ref_pic_info.frame_num + 1) % self.curr_info.max_frame_num
        {
            self.handle_frame_num_gap(frame_num, timestamp)?;
        }

        let first_field = self.find_first_field(slice)?;
        self.init_current_pic(slice, first_field.clone(), timestamp)?;

        let cur_pic = self.cur_pic.as_ref().unwrap();

        if matches!(cur_pic.is_idr, IsIdr::Yes { .. }) {
            // C.4.5.3 "Bumping process"
            // The bumping process is invoked in the following cases:
            // Clause 2:
            // The current picture is an IDR picture and
            // no_output_of_prior_pics_flag is not equal to 1 and is not
            // inferred to be equal to 1, as specified in clause C.4.4.
            if !cur_pic.ref_pic_marking.no_output_of_prior_pics_flag() {
                self.drain()?;
            } else {
                // C.4.4 When no_output_of_prior_pics_flag is equal to 1 or is
                // inferred to be equal to 1, all frame buffers in the DPB are
                // emptied without output of the pictures they contain, and DPB
                // fullness is set to 0.
                self.dpb.clear();
            }
        }

        self.update_pic_nums(i32::from(slice.header().frame_num()), None)?;
        self.init_ref_pic_lists();

        debug!(
            "Decode picture POC {:?}",
            self.cur_pic.as_ref().unwrap().pic_order_cnt
        );

        if let Some(first_field) = first_field {
            self.backend.new_field_picture(
                self.cur_pic.as_ref().unwrap(),
                timestamp,
                &first_field,
            )?;
        } else {
            self.backend
                .new_picture(self.cur_pic.as_ref().unwrap(), timestamp)?;
        }

        self.backend.handle_picture(
            self.cur_pic.as_ref().unwrap(),
            timestamp,
            self.parser
                .get_sps(self.cur_sps_id)
                .context("Invalid SPS in handle_picture")?,
            self.parser
                .get_pps(self.cur_pps_id)
                .context("invalid PPS in handle_picture")?,
            &self.dpb,
            slice,
        )?;

        Ok(())
    }

    fn pic_num_f(handle: &T, max_pic_num: i32) -> i32 {
        let pic = handle.picture();

        if !matches!(pic.reference(), Reference::LongTerm) {
            pic.pic_num
        } else {
            max_pic_num
        }
    }

    fn long_term_pic_num_f(handle: &T, max_long_term_frame_idx: i32) -> i32 {
        let pic = handle.picture();

        if matches!(pic.reference(), Reference::LongTerm) {
            pic.long_term_pic_num
        } else {
            2 * (max_long_term_frame_idx + 1)
        }
    }

    // Copies from the per-picture lists into the per-slice lists.
    fn copy_into_ref_pic_list(
        &mut self,
        ref_pic_list: RefPicList,
        ref_pic_list_name: RefPicListName,
    ) {
        let src = match ref_pic_list_name {
            RefPicListName::P0 => &mut self.ref_pic_list_p0,
            RefPicListName::B0 => &mut self.ref_pic_list_b0,
            RefPicListName::B1 => &mut self.ref_pic_list_b1,
        };

        let dst = match ref_pic_list {
            RefPicList::RefPicList0 => &mut self.ref_pic_list0,
            RefPicList::RefPicList1 => &mut self.ref_pic_list1,
        };

        dst.clear();
        dst.extend(src.iter().cloned());
    }

    // 8.2.4.3.1 Modification process of reference picture lists for short-term
    // reference pictures
    fn short_term_pic_list_modification(
        &mut self,
        current_slice: &Slice<impl AsRef<[u8]>>,
        ref_pic_list: RefPicList,
        rplm: &RefPicListModification,
        pic_num_lx_pred: &mut i32,
        ref_idx_lx: &mut usize,
    ) -> Result<()> {
        let pic_num_lx_no_wrap;
        let abs_diff_pic_num = rplm.abs_diff_pic_num_minus1() as i32 + 1;
        let modification_of_pic_nums_idc = rplm.modification_of_pic_nums_idc();
        let current_pic = self.cur_pic.as_ref().unwrap();

        if modification_of_pic_nums_idc == 0 {
            if *pic_num_lx_pred - abs_diff_pic_num < 0 {
                pic_num_lx_no_wrap =
                    *pic_num_lx_pred - abs_diff_pic_num + self.curr_info.max_pic_num;
            } else {
                pic_num_lx_no_wrap = *pic_num_lx_pred - abs_diff_pic_num;
            }
        } else if modification_of_pic_nums_idc == 1 {
            if *pic_num_lx_pred + abs_diff_pic_num >= self.curr_info.max_pic_num {
                pic_num_lx_no_wrap =
                    *pic_num_lx_pred + abs_diff_pic_num - self.curr_info.max_pic_num;
            } else {
                pic_num_lx_no_wrap = *pic_num_lx_pred + abs_diff_pic_num;
            }
        } else {
            panic!(
                "Unexpected value for modification_of_pic_nums_idc {:?}",
                rplm.modification_of_pic_nums_idc()
            );
        }

        *pic_num_lx_pred = pic_num_lx_no_wrap;

        let pic_num_lx = if pic_num_lx_no_wrap > current_pic.pic_num {
            pic_num_lx_no_wrap - self.curr_info.max_pic_num
        } else {
            pic_num_lx_no_wrap
        };

        let handle = self
            .dpb
            .find_short_term_with_pic_num(pic_num_lx)
            .with_context(|| format!("No ShortTerm reference found with pic_num {}", pic_num_lx))?;

        let ref_pic_list_x = match ref_pic_list {
            RefPicList::RefPicList0 => &mut self.ref_pic_list0,
            RefPicList::RefPicList1 => &mut self.ref_pic_list1,
        };

        ref_pic_list_x.insert(*ref_idx_lx, handle);
        *ref_idx_lx += 1;

        let num_ref_idx_lx_active_minus1 = match ref_pic_list {
            RefPicList::RefPicList0 => current_slice.header().num_ref_idx_l0_active_minus1(),
            RefPicList::RefPicList1 => current_slice.header().num_ref_idx_l1_active_minus1(),
        };

        let mut nidx = *ref_idx_lx;

        for cidx in *ref_idx_lx..=usize::from(num_ref_idx_lx_active_minus1) {
            if cidx == ref_pic_list_x.len() {
                break;
            }

            let target = &ref_pic_list_x[cidx].clone();
            let max_pic_num = self.curr_info.max_pic_num;

            if Self::pic_num_f(target, max_pic_num) != pic_num_lx {
                ref_pic_list_x[nidx] = ref_pic_list_x[cidx].clone();
                nidx += 1;
            }
        }

        while ref_pic_list_x.len() > (usize::from(num_ref_idx_lx_active_minus1) + 1) {
            ref_pic_list_x.pop();
        }

        Ok(())
    }

    fn long_term_pic_list_modification(
        &mut self,
        current_slice: &Slice<impl AsRef<[u8]>>,
        ref_pic_list: RefPicList,
        rplm: &RefPicListModification,
        ref_idx_lx: &mut usize,
    ) -> Result<()> {
        let long_term_pic_num = rplm.long_term_pic_num();

        let handle = self
            .dpb
            .find_long_term_with_long_term_pic_num(long_term_pic_num as i32)
            .with_context(|| {
                format!(
                    "No LongTerm reference found with long_term_pic_num {}",
                    long_term_pic_num
                )
            })?;

        let ref_pic_list_x = match ref_pic_list {
            RefPicList::RefPicList0 => &mut self.ref_pic_list0,
            RefPicList::RefPicList1 => &mut self.ref_pic_list1,
        };

        ref_pic_list_x.insert(*ref_idx_lx, handle);
        *ref_idx_lx += 1;

        let mut nidx = *ref_idx_lx;

        let num_ref_idx_lx_active_minus1 = match ref_pic_list {
            RefPicList::RefPicList0 => current_slice.header().num_ref_idx_l0_active_minus1(),
            RefPicList::RefPicList1 => current_slice.header().num_ref_idx_l1_active_minus1(),
        };

        for cidx in *ref_idx_lx..=usize::from(num_ref_idx_lx_active_minus1) {
            if cidx == ref_pic_list_x.len() {
                break;
            }

            let target = ref_pic_list_x[cidx].clone();
            let max_long_term_frame_idx = self.curr_info.max_long_term_frame_idx;

            if Self::long_term_pic_num_f(&target, max_long_term_frame_idx)
                != long_term_pic_num as i32
            {
                ref_pic_list_x[nidx] = ref_pic_list_x[cidx].clone();
                nidx += 1;
            }
        }

        while ref_pic_list_x.len() > (usize::from(num_ref_idx_lx_active_minus1) + 1) {
            ref_pic_list_x.pop();
        }

        Ok(())
    }

    fn modify_ref_pic_list(
        &mut self,
        current_slice: &Slice<impl AsRef<[u8]>>,
        ref_pic_list: RefPicList,
    ) -> Result<()> {
        let hdr = current_slice.header();

        let ref_pic_list_modification_flag_lx = match ref_pic_list {
            RefPicList::RefPicList0 => hdr.ref_pic_list_modification_flag_l0(),
            RefPicList::RefPicList1 => hdr.ref_pic_list_modification_flag_l1(),
        };

        let (ref_pic_list_x, num_ref_idx_lx_active_minus1, rplm) = match ref_pic_list {
            RefPicList::RefPicList0 => (
                &mut self.ref_pic_list0,
                hdr.num_ref_idx_l0_active_minus1(),
                hdr.ref_pic_list_modification_l0(),
            ),
            RefPicList::RefPicList1 => (
                &mut self.ref_pic_list1,
                hdr.num_ref_idx_l1_active_minus1(),
                hdr.ref_pic_list_modification_l1(),
            ),
        };

        while ref_pic_list_x.len() > (usize::from(num_ref_idx_lx_active_minus1) + 1) {
            ref_pic_list_x.pop();
        }

        if !ref_pic_list_modification_flag_lx {
            return Ok(());
        }

        let mut pic_num_lx_pred = self.cur_pic.as_ref().unwrap().pic_num;
        let mut ref_idx_lx = 0;

        for modification in rplm {
            let idc = modification.modification_of_pic_nums_idc();

            match idc {
                0 | 1 => {
                    self.short_term_pic_list_modification(
                        current_slice,
                        ref_pic_list,
                        modification,
                        &mut pic_num_lx_pred,
                        &mut ref_idx_lx,
                    )?;
                }
                2 => self.long_term_pic_list_modification(
                    current_slice,
                    ref_pic_list,
                    modification,
                    &mut ref_idx_lx,
                )?,
                3 => break,
                _ => panic!("Unexpected modification_of_pic_nums_idc {:?}", idc),
            }
        }

        Ok(())
    }

    fn modify_ref_pic_lists(&mut self, current_slice: &Slice<impl AsRef<[u8]>>) -> Result<()> {
        self.ref_pic_list0.clear();
        self.ref_pic_list1.clear();

        if let SliceType::P | SliceType::Sp = current_slice.header().slice_type() {
            self.copy_into_ref_pic_list(RefPicList::RefPicList0, RefPicListName::P0);
            self.modify_ref_pic_list(current_slice, RefPicList::RefPicList0)
        } else if let SliceType::B = current_slice.header().slice_type() {
            self.copy_into_ref_pic_list(RefPicList::RefPicList0, RefPicListName::B0);
            self.copy_into_ref_pic_list(RefPicList::RefPicList1, RefPicListName::B1);
            self.modify_ref_pic_list(current_slice, RefPicList::RefPicList0)
                .and(self.modify_ref_pic_list(current_slice, RefPicList::RefPicList1))
        } else {
            Ok(())
        }
    }

    /// Handle a slice. Called once per slice NALU.
    fn handle_slice(&mut self, timestamp: u64, slice: &Slice<&dyn AsRef<[u8]>>) -> Result<()> {
        let cur_pic = self.cur_pic.as_ref().unwrap();
        if self.dpb.interlaced()
            && matches!(cur_pic.field, Field::Frame)
            && !cur_pic.is_second_field()
        {
            let prev_field = cur_pic.field;
            let cur_field = if slice.header().field_pic_flag() {
                if slice.header().bottom_field_flag() {
                    Field::Bottom
                } else {
                    Field::Top
                }
            } else {
                Field::Frame
            };

            let new_field_picture = cur_field != prev_field;

            if new_field_picture {
                let handle = self.submit_picture()?;
                self.finish_picture(handle)?;
                self.handle_picture(timestamp, slice)?;
            }
        }

        self.curr_info.max_pic_num = slice.header().max_pic_num() as i32;
        self.modify_ref_pic_lists(slice)?;

        let sps = self
            .parser
            .get_sps(self.cur_sps_id)
            .context("Invalid SPS in handle_slice")?;

        let pps = self
            .parser
            .get_pps(self.cur_pps_id)
            .context("Invalid PPS in handle_slice")?;

        self.backend.decode_slice(
            slice,
            sps,
            pps,
            &self.dpb,
            &self.ref_pic_list0,
            &self.ref_pic_list1,
        )?;

        Ok(())
    }

    /// Submits the picture to the accelerator.
    fn submit_picture(&mut self) -> VideoDecoderResult<T> {
        let picture = self.cur_pic.take().unwrap();

        let block = matches!(self.blocking_mode, BlockingMode::Blocking)
            || matches!(
                self.negotiation_status,
                NegotiationStatus::DrainingQueuedBuffers
            );

        self.backend
            .submit_picture(picture, block)
            .map_err(VideoDecoderError::StatelessBackendError)
    }

    pub fn get_raster_from_zigzag_8x8(src: [u8; 64], dst: &mut [u8; 64]) {
        for i in 0..64 {
            dst[i] = src[ZIGZAG_8X8[i] as usize];
        }
    }

    pub fn get_raster_from_zigzag_4x4(src: [u8; 16], dst: &mut [u8; 16]) {
        for i in 0..16 {
            dst[i] = src[ZIGZAG_4X4[i] as usize];
        }
    }

    fn peek_sps(parser: &mut Parser, bitstream: &[u8]) -> Option<Sps> {
        let mut cursor = Cursor::new(bitstream);

        while let Ok(Some(nalu)) = Nalu::next(&mut cursor, bitstream) {
            if matches!(nalu.header().nalu_type(), NaluType::Sps) {
                let sps = parser.parse_sps(&nalu).ok()?;
                return Some(sps.clone());
            }
        }

        None
    }

    #[cfg(test)]
    fn steal_pics_for_test(&mut self) {
        let frames = self.get_ready_frames();
        self.params.save_ready_pics(frames);
    }

    #[cfg(test)]
    pub fn backend(&self) -> &dyn StatelessDecoderBackend<Handle = T> {
        self.backend.as_ref()
    }

    #[cfg(test)]
    pub fn backend_mut(&mut self) -> &mut dyn StatelessDecoderBackend<Handle = T> {
        self.backend.as_mut()
    }

    fn decode_access_unit(
        &mut self,
        timestamp: u64,
        bitstream: &dyn AsRef<[u8]>,
    ) -> VideoDecoderResult<()> {
        if self.backend.num_resources_left() == 0 {
            return Err(VideoDecoderError::StatelessBackendError(
                StatelessBackendError::OutOfResources,
            ));
        }

        let mut cursor = Cursor::new(bitstream);

        while let Ok(Some(nalu)) = Nalu::next(&mut cursor, &bitstream) {
            match nalu.header().nalu_type() {
                NaluType::Sps => {
                    self.process_sps(&nalu)?;
                }

                NaluType::Pps => {
                    self.parser.parse_pps(&nalu)?;
                }

                NaluType::Slice
                | NaluType::SliceDpa
                | NaluType::SliceDpb
                | NaluType::SliceDpc
                | NaluType::SliceIdr
                | NaluType::SliceExt => {
                    let slice = self.parser.parse_slice_header(nalu)?;
                    if self.cur_pic.is_none() {
                        self.handle_picture(timestamp, &slice)?;
                    }

                    self.handle_slice(timestamp, &slice)?;
                }

                other => {
                    debug!("Unsupported NAL unit type {:?}", other,);
                }
            }
        }

        let handle = self.submit_picture()?;
        self.finish_picture(handle)?;

        Ok(())
    }

    fn block_on_one(&mut self) -> VideoDecoderResult<()> {
        for handle in &self.ready_queue {
            if !self.backend.handle_is_ready(handle) {
                return self
                    .backend
                    .block_on_handle(handle)
                    .map_err(VideoDecoderError::StatelessBackendError);
            }
        }

        Ok(())
    }
}

impl<T> VideoDecoder for Decoder<T>
where
    T: DecodedHandle<CodecData = PictureData<<T as DecodedHandle>::BackendHandle>>
        + DynDecodedHandle
        + 'static,
{
    fn decode(
        &mut self,
        timestamp: u64,
        bitstream: &dyn AsRef<[u8]>,
    ) -> VideoDecoderResult<Vec<Box<dyn DynDecodedHandle>>> {
        let sps = Self::peek_sps(&mut self.parser, bitstream.as_ref());

        if let Some(sps) = &sps {
            if Self::negotiation_possible(sps, &self.dpb, self.coded_resolution)? {
                if matches!(self.negotiation_status, NegotiationStatus::Negotiated) {
                    self.negotiation_status = NegotiationStatus::NonNegotiated {
                        queued_buffers: Default::default(),
                    }
                }
            }
        }

        let queued_buffers = match &mut self.negotiation_status {
            NegotiationStatus::NonNegotiated { queued_buffers } => {
                let buffer = Vec::from(bitstream.as_ref());
                queued_buffers.push((timestamp, buffer));

                if let Some(sps) = &sps {
                    let max_dpb_frames = Self::max_dpb_frames(sps)?;

                    self.backend.poll(BlockingMode::Blocking)?;
                    self.backend.new_sequence(sps, max_dpb_frames)?;

                    self.negotiation_status = NegotiationStatus::Possible {
                        queued_buffers: queued_buffers.clone(),
                    }
                }

                return Ok(vec![]);
            }

            NegotiationStatus::Possible { queued_buffers } => {
                let queued_buffers = queued_buffers.clone();
                self.negotiation_status = NegotiationStatus::DrainingQueuedBuffers;
                Some(queued_buffers)
            }

            NegotiationStatus::DrainingQueuedBuffers | NegotiationStatus::Negotiated => None,
        };

        if let Some(queued_buffers) = queued_buffers {
            for (timestamp, buffer) in queued_buffers {
                self.decode_access_unit(timestamp, &buffer)?;
            }

            self.negotiation_status = NegotiationStatus::Negotiated;
        }

        self.decode_access_unit(timestamp, bitstream)?;

        if self.backend.num_resources_left() == 0 {
            self.block_on_one()?;
        }

        self.backend.poll(self.blocking_mode)?;

        #[cfg(test)]
        self.steal_pics_for_test();

        let ready_frames = self.get_ready_frames();

        Ok(ready_frames
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }

    fn flush(&mut self) -> VideoDecoderResult<Vec<Box<dyn DynDecodedHandle>>> {
        // Decode whatever is pending using the default format. Mainly covers
        // the rare case where only one buffer is sent.
        match &self.negotiation_status {
            NegotiationStatus::NonNegotiated { queued_buffers }
            | NegotiationStatus::Possible { queued_buffers } => {
                for (timestamp, buffer) in queued_buffers.clone() {
                    self.decode_access_unit(timestamp, &buffer)?;
                }
            }
            _ => {}
        }

        self.drain()?;

        #[cfg(test)]
        self.steal_pics_for_test();

        let pics = self.get_ready_frames();

        Ok(pics
            .into_iter()
            .map(|h| Box::new(h) as Box<dyn DynDecodedHandle>)
            .collect())
    }

    fn backend(&self) -> &dyn VideoDecoderBackend {
        self.backend.as_video_decoder_backend()
    }

    fn backend_mut(&mut self) -> &mut dyn VideoDecoderBackend {
        self.backend.as_video_decoder_backend_mut()
    }

    fn negotiation_possible(&self) -> bool {
        matches!(self.negotiation_status, NegotiationStatus::Possible { .. })
    }

    fn num_resources_left(&self) -> Option<usize> {
        if matches!(
            self.negotiation_status,
            NegotiationStatus::NonNegotiated { .. }
        ) {
            return None;
        }

        let left_in_the_backend = self.backend.num_resources_left();

        if let NegotiationStatus::Possible { queued_buffers } = &self.negotiation_status {
            Some(left_in_the_backend - queued_buffers.len())
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

    use crate::decoders::h264::decoder::Decoder;
    use crate::decoders::h264::nalu_reader::NaluReader;
    use crate::decoders::h264::parser::Nalu;
    use crate::decoders::h264::parser::NaluType;
    use crate::decoders::h264::picture::PictureData;
    use crate::decoders::BlockingMode;
    use crate::decoders::DecodedHandle;
    use crate::decoders::DynDecodedHandle;
    use crate::decoders::VideoDecoder;
    use crate::utils::dummy::Backend;

    pub fn process_ready_frames<Handle>(
        decoder: &mut Decoder<Handle>,
        action: &mut dyn FnMut(&mut Decoder<Handle>, &Handle),
    ) where
        Handle: DecodedHandle<CodecData = PictureData<<Handle as DecodedHandle>::BackendHandle>>
            + DynDecodedHandle,
    {
        let ready_pics = decoder.params.ready_pics.drain(..).collect::<Vec<_>>();

        for handle in ready_pics {
            action(decoder, &handle);
        }
    }

    pub fn run_decoding_loop<Handle, F>(
        decoder: &mut Decoder<Handle>,
        test_stream: &[u8],
        mut on_new_iteration: F,
    ) where
        Handle: DecodedHandle<CodecData = PictureData<<Handle as DecodedHandle>::BackendHandle>>
            + DynDecodedHandle
            + 'static,
        F: FnMut(&mut Decoder<Handle>),
    {
        let mut cursor = Cursor::new(test_stream);

        let mut aud_parser = AccessUnitParser::default();
        let mut frame_num = 0;

        while let Ok(Some(nalu)) = Nalu::next(&mut cursor, test_stream) {
            if let Some(access_unit) = aud_parser.accumulate(nalu) {
                let start_nalu = access_unit.nalus.first().unwrap();
                let end_nalu = access_unit.nalus.last().unwrap();

                let start_offset = start_nalu.sc_offset();
                let end_offset = end_nalu.offset() + end_nalu.size();

                let data = &test_stream[start_offset..end_offset];

                decoder.decode(frame_num, &data).unwrap();

                on_new_iteration(decoder);
                frame_num += 1;
            }
        }

        // Process any left over NALUs, even if we could not fit them into an AU using the heuristic.
        #[allow(unused_assignments)]
        if aud_parser.nalus.len() > 0 {
            let start_nalu = aud_parser.nalus.first().unwrap();
            let end_nalu = aud_parser.nalus.last().unwrap();

            let start_offset = start_nalu.sc_offset();
            let end_offset = end_nalu.offset() + end_nalu.size();

            let data = &test_stream[start_offset..end_offset];

            decoder.decode(frame_num, &data).unwrap();

            on_new_iteration(decoder);
            frame_num += 1;
        }

        decoder.flush().unwrap();
        let n_flushed = decoder.params.ready_pics.len();

        for _ in 0..n_flushed {
            on_new_iteration(decoder);
        }
    }

    /// Represents an Access Unit.
    #[derive(Debug, Default)]
    pub struct AccessUnit<T> {
        pub nalus: Vec<Nalu<T>>,
    }

    /// A parser that produces Access Units from a list of NALUs. It does not use
    /// section 7.4.1.2.4 of the specification for the detection of the first VCL
    /// NAL unit of a primary coded picture and instead uses an heuristic from
    /// GStreamer that works well enough for most streams.
    #[derive(Debug, Default)]
    pub struct AccessUnitParser<T> {
        picture_started: bool,
        nalus: Vec<Nalu<T>>,
    }

    impl<T: AsRef<[u8]>> AccessUnitParser<T> {
        /// Use GStreamer's gsth264parse's heuristic to break into access units.
        /// Only yields back an access unit if:
        /// We had previously established that a picture had started and an AUD is seen.
        /// We had previously established that a picture had started, but SEI|SPS|PPS is seen.
        /// We had previously established that a picture had started, and the
        /// current slice refers to the next picture.
        pub fn accumulate(&mut self, nalu: Nalu<T>) -> Option<AccessUnit<T>> {
            if matches!(nalu.header().nalu_type(), NaluType::AuDelimiter) && self.picture_started {
                self.picture_started = false;
                return Some(AccessUnit {
                    nalus: self.nalus.drain(..).collect::<Vec<_>>(),
                });
            }

            self.nalus.push(nalu);

            if !self.picture_started {
                self.picture_started = matches!(
                    self.nalus.last().unwrap().header().nalu_type(),
                    NaluType::Slice
                        | NaluType::SliceDpa
                        | NaluType::SliceDpb
                        | NaluType::SliceDpc
                        | NaluType::SliceIdr
                        | NaluType::SliceExt
                );
            } else if matches!(
                self.nalus.last().unwrap().header().nalu_type(),
                NaluType::Sei | NaluType::Sps | NaluType::Pps
            ) {
                self.picture_started = false;
                return Some(AccessUnit {
                    nalus: self.nalus.drain(..).collect::<Vec<_>>(),
                });
            } else if matches!(
                self.nalus.last().unwrap().header().nalu_type(),
                NaluType::Slice | NaluType::SliceDpa | NaluType::SliceIdr
            ) {
                let data = self.nalus.last().unwrap().data().as_ref();
                let header_bytes = self.nalus.last().unwrap().header().header_bytes();
                let mut r = NaluReader::new(&data[header_bytes..]);

                let first_mb_in_slice = r.read_ue::<u32>();

                if first_mb_in_slice.is_ok() && first_mb_in_slice.unwrap() == 0 {
                    self.picture_started = false;
                    return Some(AccessUnit {
                        nalus: self.nalus.drain(..).collect::<Vec<_>>(),
                    });
                }
            }

            None
        }
    }

    #[test]
    fn test_16x16_progressive_i() {
        /// A 16x16 progressive byte-stream encoded I-frame to make it easier to
        /// spot errors on the libva trace.
        /// Encoded with the following GStreamer pipeline:
        /// gst-launch-1.0 videotestsrc num-buffers=1 ! video/x-raw,format=I420,width=16,height=16 ! \
        /// x264enc ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
        /// filesink location="/tmp/16x16-I.h264"
        const TEST_STREAM: &[u8] = include_bytes!("test_data/16x16-I.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 1);
        }
    }

    #[test]
    fn test_16x16_progressive_i_and_p() {
        /// A 16x16 progressive byte-stream encoded I-frame and P-frame to make
        /// it easier to spot errors on the libva trace.
        /// Encoded with the following GStreamer pipeline:
        /// gst-launch-1.0 videotestsrc num-buffers=2 ! video/x-raw,format=I420,width=16,height=16 ! \
        /// x264enc b-adapt=false ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
        /// filesink location="/tmp/16x16-I-P.h264"
        const TEST_STREAM: &[u8] = include_bytes!("test_data/16x16-I-P.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 2);
        }
    }

    #[test]
    fn test_16x16_progressive_i_p_b_p() {
        /// A 16x16 progressive byte-stream encoded I-P-B-P sequence to make it
        /// easier to it easier to spot errors on the libva trace.
        /// Encoded with the following GStreamer pipeline:
        /// gst-launch-1.0 videotestsrc num-buffers=3 ! video/x-raw,format=I420,width=16,height=16 ! \
        /// x264enc b-adapt=false bframes=1 ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! \
        /// filesink location="/tmp/16x16-I-B-and-P.h264"
        const TEST_STREAM: &[u8] = include_bytes!("test_data/16x16-I-P-B-P.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 4);
        }
    }

    #[test]
    fn test_16x16_progressive_i_p_b_p_high() {
        /// A 16x16 progressive byte-stream encoded I-P-B-P sequence to make it
        /// easier to it easier to spot errors on the libva trace.
        /// Also tests whether the decoder supports the high profile.
        ///
        /// Encoded with the following GStreamer pipeline:
        /// gst-launch-1.0 videotestsrc num-buffers=3 ! video/x-raw,format=I420,width=16,height=16 ! \
        /// x264enc b-adapt=false bframes=1 ! video/x-h264,profile=high,stream-format=byte-stream ! \
        /// filesink location="/tmp/16x16-I-B-and-P-high.h264"
        const TEST_STREAM: &[u8] = include_bytes!("test_data/16x16-I-P-B-P-high.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 4);
        }
    }

    #[test]
    fn test_interlaced_kodi_1080i() {
        /// A 1080i example from the Kodi samples, available at
        /// https://drive.google.com/file/d/0BwxFVkl63-lEbFBzak1sbmU1N0E/view?usp=sharing&resourcekey=0-GOK3gZYAmP-ywn6T9zCDoQ
        ///
        /// Note that fair use is claimed on all non-copyleft clips, as their
        /// the purpose is only for testing, technical evaluation, and
        /// documentation.
        ///
        /// The clip was demuxed on GStreamer and only the first 32 buffers were kept.
        ///
        /// The pipeline used was:
        /// gst-launch-1.0 filesrc location="1080i-25-H264.mkv" ! matroskademux ! h264parse ! \
        /// video/x-h264,stream-format=byte-stream ! identity eos-after = 33 ! \
        /// filesink location="test-kodi-1080i-25-H264.h264"
        ///
        /// This test helps ensure that the interlaced logic actually works in the decoder.
        /// We loop through the buffers and unwrap the calls to decode() to make sure there
        /// are no errors that would make the decoder abort.
        ///
        /// We also test the flush implementation, to make sure we can empty the DPB correctly even
        /// in interlaced mode.
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-kodi-1080i-25-H264.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            /* 32 fields, 16 frames */
            assert_eq!(frame_num, 16);
        }
    }

    #[test]
    fn test_kodi_1080p() {
        /// A 1080p example from the Kodi samples, available at
        /// https://drive.google.com/file/d/0BwxFVkl63-lEdzlZZ2lCLTVLa2c/view?resourcekey=0-iCq6zrc9whsrif4-Zvu0DQ
        ///
        /// Note that fair use is claimed on all non-copyleft clips, as their
        /// the purpose is only for testing, technical evaluation, and
        /// documentation.
        ///
        /// The clip was demuxed on GStreamer and only the first 30 buffers were kept.
        ///
        /// The pipeline used was:
        /// gst-launch-1.0 filesrc location="/tmp/FPS_test_1080p24_L4.1.mkv" ! \
        /// matroskademux ! h264parse ! video/x-h264,stream-format=byte-stream ! \
        /// identity eos-after=31 ! filesink location = "/tmp/FPS_test_1080p24_l4_1.h264"
        const TEST_STREAM: &[u8] = include_bytes!("test_data/FPS_test_1080p24_l4_1.h264");
        let blocking_modes = [BlockingMode::Blocking, BlockingMode::NonBlocking];

        for blocking_mode in blocking_modes {
            let mut frame_num = 0;
            let backend = Box::new(Backend {});
            let mut decoder = Decoder::new(backend, blocking_mode).unwrap();

            run_decoding_loop(&mut decoder, TEST_STREAM, |decoder| {
                process_ready_frames(decoder, &mut |_, _| frame_num += 1);
            });

            assert_eq!(frame_num, 30);
        }
    }

    #[test]
    fn test_25fps_interlaced_h264() {
        // Adapted from Chromium's test-25fps.h264. Same file, but encoded as
        // interlaced instead using the following ffmpeg command:
        // ffmpeg -i
        // src/third_party/blink/web_tests/media/content/test-25fps.mp4
        // -flags +ilme+ildct  -vbsf h264_mp4toannexb -an test-25fps.h264
        //
        // This test makes sure that the interlaced logic in the decoder
        // actually works, specially that "frame splitting" works, as the fields
        // here were encoded as frames.
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-25fps-interlaced.h264");
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

    #[test]
    /// Same as Chromium's test-25fps.h264
    fn test_25fps_h264() {
        const TEST_STREAM: &[u8] = include_bytes!("test_data/test-25fps.h264");
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

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::rc::Rc;
use std::rc::Weak;

use log::debug;

use crate::decoders::h264::parser::RefPicMarking;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::SliceType;
use crate::decoders::h264::parser::Sps;
use crate::decoders::FrameInfo;
use crate::Resolution;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Field {
    #[default]
    Frame,
    Top,
    Bottom,
}

impl Field {
    /// Returns the field of opposite parity.
    pub fn opposite(&self) -> Option<Self> {
        match *self {
            Field::Frame => None,
            Field::Top => Some(Field::Bottom),
            Field::Bottom => Some(Field::Top),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Reference {
    #[default]
    None,
    ShortTerm,
    LongTerm,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum IsIdr {
    #[default]
    No,
    Yes {
        idr_pic_id: u16,
    },
}

#[derive(Default)]
pub struct PictureData {
    pub pic_order_cnt_type: u8,
    pub top_field_order_cnt: i32,
    pub bottom_field_order_cnt: i32,
    pub pic_order_cnt: i32,
    pub pic_order_cnt_msb: i32,
    pub pic_order_cnt_lsb: i32,
    pub delta_pic_order_cnt_bottom: i32,
    pub delta_pic_order_cnt0: i32,
    pub delta_pic_order_cnt1: i32,

    pub pic_num: i32,
    pub long_term_pic_num: i32,
    pub frame_num: i32,
    pub frame_num_offset: i32,
    pub frame_num_wrap: i32,
    pub long_term_frame_idx: i32,

    pub coded_resolution: Resolution,
    pub display_resolution: Resolution,

    pub type_: SliceType,
    pub nal_ref_idc: u8,
    pub is_idr: IsIdr,
    reference: Reference,
    pub ref_pic_list_modification_flag_l0: i32,
    pub abs_diff_pic_num_minus1: i32,
    pub needed_for_output: bool,

    // Does memory management op 5 needs to be executed after this
    // picture has finished decoding?
    pub has_mmco_5: bool,

    // Created by the decoding process for gaps in frame_num.
    // Not for decode or output.
    pub nonexisting: bool,

    pub field: Field,

    // Values from slice_hdr to be used during reference marking and
    // memory management after finishing this picture.
    pub ref_pic_marking: RefPicMarking,

    is_second_field: bool,
    other_field: Option<Weak<RefCell<Self>>>,

    pub timestamp: u64,
}

impl PictureData {
    pub fn new_non_existing(frame_num: i32, timestamp: u64) -> Self {
        PictureData {
            frame_num,
            nonexisting: true,
            nal_ref_idc: 1,
            field: Field::Frame,
            pic_num: frame_num,
            reference: Reference::ShortTerm,
            timestamp,
            ..Default::default()
        }
    }

    pub fn new_from_slice(slice: &Slice<&[u8]>, sps: &Sps, timestamp: u64) -> Self {
        let hdr = slice.header();
        let nalu_hdr = slice.nalu().header();

        let is_idr = if nalu_hdr.idr_pic_flag() {
            IsIdr::Yes {
                idr_pic_id: hdr.idr_pic_id(),
            }
        } else {
            IsIdr::No
        };

        let field = if hdr.field_pic_flag() {
            if hdr.bottom_field_flag() {
                Field::Bottom
            } else {
                Field::Top
            }
        } else {
            Field::Frame
        };

        let reference = if nalu_hdr.ref_idc() != 0 {
            Reference::ShortTerm
        } else {
            Reference::None
        };

        let pic_num = if !hdr.field_pic_flag() {
            hdr.frame_num()
        } else {
            2 * hdr.frame_num() + 1
        };

        let (
            pic_order_cnt_lsb,
            delta_pic_order_cnt_bottom,
            delta_pic_order_cnt0,
            delta_pic_order_cnt1,
        ) = match sps.pic_order_cnt_type() {
            0 => (
                hdr.pic_order_cnt_lsb(),
                hdr.delta_pic_order_cnt_bottom(),
                Default::default(),
                Default::default(),
            ),
            1 => (
                Default::default(),
                Default::default(),
                hdr.delta_pic_order_cnt()[0],
                hdr.delta_pic_order_cnt()[1],
            ),
            _ => (
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            ),
        };

        let width = sps.width();
        let height = sps.height();
        let coded_resolution = Resolution { width, height };

        let visible_rect = sps.visible_rectangle();

        let display_resolution = Resolution {
            width: visible_rect.max.x - visible_rect.min.x,
            height: visible_rect.max.y - visible_rect.min.y,
        };

        PictureData {
            pic_order_cnt_type: sps.pic_order_cnt_type(),
            pic_order_cnt_lsb: i32::from(pic_order_cnt_lsb),
            delta_pic_order_cnt_bottom,
            delta_pic_order_cnt0,
            delta_pic_order_cnt1,
            pic_num: i32::from(pic_num),
            frame_num: i32::from(hdr.frame_num()),
            nal_ref_idc: nalu_hdr.ref_idc(),
            is_idr,
            reference,
            field,
            ref_pic_marking: hdr.dec_ref_pic_marking().clone(),
            coded_resolution,
            display_resolution,
            timestamp,
            ..Default::default()
        }
    }

    /// Whether the current picture is a reference, either ShortTerm or LongTerm.
    pub fn is_ref(&self) -> bool {
        !matches!(self.reference, Reference::None)
    }

    /// Whether this picture is a second field.
    pub fn is_second_field(&self) -> bool {
        self.is_second_field
    }

    /// Returns a reference to the picture's Reference
    pub fn reference(&self) -> &Reference {
        &self.reference
    }

    /// Mark the picture as a reference picture.
    pub fn set_reference(&mut self, reference: Reference, apply_to_other_field: bool) {
        log::debug!("Set reference of {:#?} to {:?}", self, reference);
        //debug
        if self.pic_order_cnt == 18 && matches!(reference, Reference::ShortTerm) {
            println!("debug");
        }
        self.reference = reference;

        if apply_to_other_field {
            if let Some(other_field) = self.other_field.as_mut() {
                log::debug!(
                    "other_field: Set reference of {:#?} to {:?}",
                    &other_field.upgrade().unwrap().borrow_mut(),
                    reference
                );
                other_field.upgrade().unwrap().borrow_mut().reference = reference;
            }
        }
    }

    /// Returns the other field when we know it must be there.
    pub fn other_field_unchecked(&self) -> Rc<RefCell<Self>> {
        self.other_field.as_ref().unwrap().upgrade().unwrap()
    }

    /// Get a reference to the picture's other field, if any.
    pub fn other_field(&self) -> Option<&Weak<RefCell<PictureData>>> {
        self.other_field.as_ref()
    }

    /// Set this picture's second field.
    pub fn set_second_field_to(&mut self, other_field: &Rc<RefCell<Self>>) {
        self.other_field = Some(Rc::downgrade(other_field));
        other_field.borrow_mut().is_second_field = true;
    }

    /// Whether the current picture is the second field of a complementary ref pair.
    pub fn is_second_field_of_complementary_ref_pair(&self) -> bool {
        self.is_ref() && self.is_second_field && self.other_field_unchecked().borrow().is_ref()
    }

    /// Set this picture's first field.
    pub fn set_first_field_to(&mut self, other_field: &Rc<RefCell<Self>>) {
        self.other_field = Some(Rc::downgrade(other_field));
        self.is_second_field = true;
    }

    /// Split a frame into two complementary fields.
    pub fn split_frame(pic_rc: &Rc<RefCell<Self>>) -> Rc<RefCell<Self>> {
        assert!(matches!(pic_rc.borrow().field, Field::Frame));
        assert!(pic_rc.borrow().other_field.is_none());

        let field;
        let pic_order_cnt;
        let mut pic = pic_rc.borrow_mut();

        debug!(
            "Splitting picture (frame_num, POC) ({:?}, {:?})",
            pic.frame_num, pic.pic_order_cnt
        );

        if pic.top_field_order_cnt < pic.bottom_field_order_cnt {
            pic.field = Field::Top;
            pic.pic_order_cnt = pic.top_field_order_cnt;

            field = Field::Bottom;
            pic_order_cnt = pic.bottom_field_order_cnt;
        } else {
            pic.field = Field::Bottom;
            pic.pic_order_cnt = pic.bottom_field_order_cnt;

            field = Field::Top;
            pic_order_cnt = pic.top_field_order_cnt;
        }

        let mut other_field = PictureData {
            top_field_order_cnt: pic.top_field_order_cnt,
            bottom_field_order_cnt: pic.bottom_field_order_cnt,
            frame_num: pic.frame_num,
            reference: pic.reference,
            nonexisting: pic.nonexisting,
            pic_order_cnt,
            field,
            ..Default::default()
        };

        other_field.is_second_field = true;
        other_field.other_field = Some(Rc::downgrade(pic_rc));

        pic.other_field = Some(Rc::downgrade(pic_rc));

        debug!(
            "Split into picture (frame_num, POC) ({:?}, {:?}), field: {:?}",
            pic.frame_num, pic.pic_order_cnt, pic.field
        );
        debug!(
            "Split into picture (frame_num, POC) ({:?}, {:?}), field {:?}",
            other_field.frame_num, other_field.pic_order_cnt, other_field.field
        );

        Rc::new(RefCell::new(other_field))
    }
}

impl FrameInfo for PictureData {
    fn display_resolution(&self) -> Resolution {
        self.display_resolution
    }
}

impl std::fmt::Debug for PictureData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PictureData")
            .field("pic_order_cnt_type", &self.pic_order_cnt_type)
            .field("top_field_order_cnt", &self.top_field_order_cnt)
            .field("bottom_field_order_cnt", &self.bottom_field_order_cnt)
            .field("pic_order_cnt", &self.pic_order_cnt)
            .field("pic_order_cnt_msb", &self.pic_order_cnt_msb)
            .field("pic_order_cnt_lsb", &self.pic_order_cnt_lsb)
            .field(
                "delta_pic_order_cnt_bottom",
                &self.delta_pic_order_cnt_bottom,
            )
            .field("delta_pic_order_cnt0", &self.delta_pic_order_cnt0)
            .field("delta_pic_order_cnt1", &self.delta_pic_order_cnt1)
            .field("pic_num", &self.pic_num)
            .field("long_term_pic_num", &self.long_term_pic_num)
            .field("frame_num", &self.frame_num)
            .field("frame_num_offset", &self.frame_num_offset)
            .field("frame_num_wrap", &self.frame_num_wrap)
            .field("long_term_frame_idx", &self.long_term_frame_idx)
            .field("coded_resolution", &self.coded_resolution)
            .field("display_resolution", &self.display_resolution)
            .field("type_", &self.type_)
            .field("nal_ref_idc", &self.nal_ref_idc)
            .field("is_idr", &self.is_idr)
            .field("reference", &self.reference)
            .field(
                "ref_pic_list_modification_flag_l0",
                &self.ref_pic_list_modification_flag_l0,
            )
            .field("abs_diff_pic_num_minus1", &self.abs_diff_pic_num_minus1)
            .field("needed_for_output", &self.needed_for_output)
            .field("has_mmco_5", &self.has_mmco_5)
            .field("nonexisting", &self.nonexisting)
            .field("field", &self.field)
            .field("ref_pic_marking", &self.ref_pic_marking)
            .field("is_second_field", &self.is_second_field)
            .field("other_field", &self.other_field)
            .finish()
    }
}

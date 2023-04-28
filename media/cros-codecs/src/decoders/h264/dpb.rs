// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Ref;
use std::cell::RefCell;
use std::cell::RefMut;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use log::debug;

use crate::decoders::h264::picture::Field;
use crate::decoders::h264::picture::IsIdr;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::h264::picture::Reference;
use crate::decoders::DecodedHandle;

// Shortcut to refer to a DPB entry.
//
// The first member of the tuple is the `PictureData` for the frame.
//
// The second member is the backend handle of the frame. It can be `None` if the inserted picture
// is non-existing (i.e. `nonexisting` is true on the `PictureData`).
#[derive(Clone)]
pub struct DpbEntry<T: DecodedHandle>(pub Rc<RefCell<PictureData>>, pub Option<T>);

pub struct Dpb<T: DecodedHandle> {
    /// List of `PictureData` and backend handles to decoded pictures.
    entries: Vec<DpbEntry<T>>,
    /// The maximum number of pictures that can be stored.
    max_num_pics: usize,
    /// Whether we're decoding in interlaced mode. Interlaced support is
    /// inspired by the GStreamer implementation, in which frames are split if
    /// interlaced=1. This makes reference marking easier. We also decode both
    /// fields to the same surface, and this surface with both fields is
    /// outputted only once.
    interlaced: bool,
}

impl<T: DecodedHandle> Dpb<T> {
    /// Returns an iterator over the underlying H264 pictures stored in the
    /// DPB.
    pub fn pictures(&self) -> impl Iterator<Item = Ref<'_, PictureData>> {
        self.entries.iter().map(|h| h.0.borrow())
    }

    /// Returns a mutable iterator over the underlying H264 pictures stored in
    /// the DPB.
    pub fn pictures_mut(&mut self) -> impl Iterator<Item = RefMut<'_, PictureData>> {
        self.entries.iter().map(|h| h.0.borrow_mut())
    }

    /// Returns the length of the DPB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Get a reference to the whole DPB entries.
    pub fn entries(&self) -> &Vec<DpbEntry<T>> {
        &self.entries
    }

    /// Set the dpb's max num pics.
    pub fn set_max_num_pics(&mut self, max_num_pics: usize) {
        self.max_num_pics = max_num_pics;
    }

    /// Get a reference to the dpb's max num pics.
    pub fn max_num_pics(&self) -> usize {
        self.max_num_pics
    }

    // Returns the number of reference frames, counting the first field only if
    // dealing with interlaced content.
    pub fn num_ref_frames(&self) -> usize {
        self.pictures()
            .filter(|p| p.is_ref() && !p.is_second_field())
            .count()
    }

    /// Get a reference to the dpb's interlaced mode.
    pub fn interlaced(&self) -> bool {
        self.interlaced
    }

    /// Set the dpb's interlaced mode.
    pub fn set_interlaced(&mut self, interlaced: bool) {
        self.interlaced = interlaced;
    }

    /// Find the short term reference picture with the lowest `frame_num_wrap`
    /// value.
    pub fn find_short_term_lowest_frame_num_wrap(&self) -> Option<Rc<RefCell<PictureData>>> {
        let lowest = self
            .entries
            .iter()
            .filter(|h| {
                let p = h.0.borrow();
                matches!(p.reference(), Reference::ShortTerm)
            })
            .cloned()
            .map(|h| h.0)
            .min_by_key(|h| {
                let p = h.borrow();
                p.frame_num_wrap
            });

        lowest
    }

    /// Mark all pictures in the DPB as unused for reference.
    pub fn mark_all_as_unused_for_ref(&mut self) {
        for mut picture in self.pictures_mut() {
            picture.set_reference(Reference::None, false);
        }
    }

    /// Remove unused pictures from the DPB. A picture is not going to be used
    /// anymore if it's a) not a reference and b) not needed for output
    pub fn remove_unused(&mut self) {
        self.entries.retain(|handle| {
            let pic = handle.0.borrow();
            let discard = !pic.is_ref() && !pic.needed_for_output;

            if discard {
                log::debug!("Removing unused picture {:#?}", pic);
            }

            !discard
        });
    }

    /// Find a short term reference picture with the given `pic_num` value.
    pub fn find_short_term_with_pic_num(&self, pic_num: i32) -> Option<DpbEntry<T>> {
        let position = self
            .pictures()
            .position(|p| matches!(p.reference(), Reference::ShortTerm) && p.pic_num == pic_num);

        log::debug!(
            "find_short_term_with_pic_num: {}, found position {:?}",
            pic_num,
            position
        );

        Some(self.entries[position?].clone())
    }

    /// Find a long term reference picture with the given `long_term_pic_num`
    /// value.
    pub fn find_long_term_with_long_term_pic_num(
        &self,
        long_term_pic_num: i32,
    ) -> Option<DpbEntry<T>> {
        let position = self.pictures().position(|p| {
            matches!(p.reference(), Reference::LongTerm) && p.long_term_pic_num == long_term_pic_num
        });

        log::debug!(
            "find_long_term_with_long_term_pic_num: {}, found position {:?}",
            long_term_pic_num,
            position
        );

        Some(self.entries[position?].clone())
    }

    /// Store a picture and its backend handle in the DPB.
    pub fn store_picture(
        &mut self,
        picture: Rc<RefCell<PictureData>>,
        handle: Option<T>,
    ) -> Result<()> {
        let max_pics = if self.interlaced {
            self.max_num_pics * 2
        } else {
            self.max_num_pics
        };

        if self.entries.len() >= max_pics {
            return Err(anyhow!("Can't add a picture to the DPB: DPB is full."));
        }

        let mut pic_mut = picture.borrow_mut();

        // C.4.2. Decoding of gaps in frame_num and storage of "non-existing"
        // pictures
        if !pic_mut.nonexisting {
            pic_mut.needed_for_output = true;
        } else {
            pic_mut.needed_for_output = false;
        }

        if pic_mut.is_second_field() {
            let first_field_rc = pic_mut.other_field_unchecked();
            drop(pic_mut);
            let mut first_field = first_field_rc.borrow_mut();
            first_field.set_second_field_to(&picture);
        } else {
            drop(pic_mut);
        }

        let pic = picture.borrow();
        debug!(
            "Stored picture POC {:?}, field {:?}, the DPB length is {:?}",
            pic.pic_order_cnt,
            pic.field,
            self.entries.len()
        );
        drop(pic);

        self.entries.push(DpbEntry(picture, handle));

        Ok(())
    }

    /// Whether the DPB has an empty slot for a new picture.
    pub fn has_empty_frame_buffer(&self) -> bool {
        if !self.interlaced {
            self.entries.len() < self.max_num_pics
        } else {
            let count = self
                .pictures()
                .filter(|pic| {
                    !pic.is_second_field()
                        && (matches!(pic.field, Field::Frame) || pic.other_field().is_some())
                })
                .count();

            count < self.max_num_pics
        }
    }

    /// Whether the DPB needs bumping, as described by clauses 1, 4, 5, 6 of
    /// C.4.5.3 "Bumping" process.
    pub fn needs_bumping(&self, to_insert: &PictureData) -> bool {
        // In C.4.5.3 we handle clauses 2 and 3 separately. All other clauses
        // check for an empty frame buffer first. Here we handle:
        //    - There is no empty frame buffer and a empty frame buffer is
        //    needed for storage of an inferred "non-existing" frame.
        //
        //    - There is no empty frame buffer and an empty frame buffer is
        //    needed for storage of a decoded (non-IDR) reference picture.
        //
        //    - There is no empty frame buffer and the current picture is a non-
        //    reference picture that is not the second field of a complementary
        //    non-reference field pair and there are pictures in the DPB that
        //    are marked as "needed for output" that precede the current
        //    non-reference picture in output order.
        //
        // Clauses 2 and 3 are handled by H264Codec::handle_picture and
        // H264Codec::finish_picture, respectively.
        if self.has_empty_frame_buffer() {
            return false;
        }

        if to_insert.nonexisting {
            return true;
        }

        let is_ref = !matches!(to_insert.reference(), Reference::None);
        let non_idr_ref = is_ref && matches!(to_insert.is_idr, IsIdr::No);

        if non_idr_ref {
            return true;
        }

        let lowest_poc = match self.find_lowest_poc_for_bumping() {
            Some(handle) => handle.0.borrow().pic_order_cnt,
            None => return false,
        };

        !to_insert.is_second_field_of_complementary_ref_pair()
            && to_insert.pic_order_cnt > lowest_poc
    }

    /// Find the lowest POC in the DPB that can be bumped.
    fn find_lowest_poc_for_bumping(&self) -> Option<DpbEntry<T>> {
        let lowest = self
            .pictures()
            .filter(|pic| {
                if !pic.needed_for_output {
                    return false;
                }

                let skip = !matches!(pic.field, Field::Frame)
                    && (pic.other_field().is_none() || pic.is_second_field());

                !skip
            })
            .min_by_key(|pic| pic.pic_order_cnt)?;

        let position = self
            .entries
            .iter()
            .position(|handle| handle.0.borrow().pic_order_cnt == lowest.pic_order_cnt)
            .unwrap();

        Some(self.entries[position].clone())
    }

    /// Gets the position of `needle` in the DPB, if any.
    fn get_position(&self, needle: &Rc<RefCell<PictureData>>) -> Option<usize> {
        self.entries
            .iter()
            .position(|handle| Rc::ptr_eq(&handle.0, needle))
    }

    /// Bump the dpb, returning a picture as per the bumping process described in C.4.5.3.
    /// Note that this picture will still be referenced by its pair, if any.
    pub fn bump(&mut self, flush: bool) -> Option<DpbEntry<T>> {
        let handle = self.find_lowest_poc_for_bumping()?;
        let mut pic = handle.0.borrow_mut();

        debug!("Bumping picture {:#?} from the dpb", pic);

        pic.needed_for_output = false;

        if !pic.is_ref() || flush {
            let index = self.get_position(&handle.0).unwrap();
            log::debug!("removed picture {:#?} from dpb", pic);
            self.entries.remove(index);
        }

        if pic.other_field().is_some() {
            let other_field_rc = pic.other_field_unchecked();
            let mut other_field = other_field_rc.borrow_mut();
            other_field.needed_for_output = false;

            if !other_field.is_ref() {
                log::debug!("other_field: removed picture {:#?} from dpb", other_field);
                let index = self.get_position(&other_field_rc).unwrap();
                self.entries.remove(index);
            }
        }

        drop(pic);
        Some(handle)
    }

    /// Drains the DPB by continuously invoking the bumping process.
    pub fn drain(&mut self) -> Vec<DpbEntry<T>> {
        debug!("Draining the DPB.");

        let mut pics = vec![];

        while let Some(pic) = self.bump(true) {
            pics.push(pic);
        }

        pics
    }

    /// Clears the DPB, dropping all the pictures.
    pub fn clear(&mut self) {
        debug!("Clearing the DPB");

        let max_num_pics = self.max_num_pics;
        let interlaced = self.interlaced;

        *self = Default::default();

        self.max_num_pics = max_num_pics;
        self.interlaced = interlaced;
    }

    /// Gets a `Vec<ContainedPicture>` of short term refs into `out`
    pub fn get_short_term_refs(&self, out: &mut Vec<DpbEntry<T>>) {
        out.extend(
            self.entries
                .iter()
                .filter(|&handle| matches!(handle.0.borrow().reference(), Reference::ShortTerm))
                .cloned(),
        )
    }

    /// Gets a `Vec<ContainedPicture>` of long term refs into `out`
    pub fn get_long_term_refs(&self, out: &mut Vec<DpbEntry<T>>) {
        out.extend(
            self.entries
                .iter()
                .filter(|&handle| matches!(handle.0.borrow().reference(), Reference::LongTerm))
                .cloned(),
        )
    }
}

impl<T: DecodedHandle> Default for Dpb<T> {
    fn default() -> Self {
        // See https://github.com/rust-lang/rust/issues/26925 on why this can't
        // be derived.
        Self {
            entries: Default::default(),
            max_num_pics: Default::default(),
            interlaced: Default::default(),
        }
    }
}

impl<T: DecodedHandle> std::fmt::Debug for Dpb<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pics = self
            .entries
            .iter()
            .map(|h| &h.0)
            .enumerate()
            .collect::<Vec<_>>();
        f.debug_struct("Dpb")
            .field("pictures", &pics)
            .field("max_num_pics", &self.max_num_pics)
            .field("interlaced", &self.interlaced)
            .finish()
    }
}

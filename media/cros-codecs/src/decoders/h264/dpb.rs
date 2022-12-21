// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::Ref;
use std::cell::RefMut;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Result;
use log::debug;

use crate::decoders::h264::backends::ContainedPicture;
use crate::decoders::h264::picture::Field;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::h264::picture::IsIdr;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::h264::picture::Reference;
use crate::decoders::DecodedHandle;

pub struct Dpb<T> {
    /// The list of handles to decoded pictures.
    handles: Vec<T>,
    /// The maximum number of pictures that can be stored.
    max_num_pics: usize,
    /// Whether we're decoding in interlaced mode. Interlaced support is
    /// inspired by the GStreamer implementation, in which frames are split if
    /// interlaced=1. This makes reference marking easier. We also decode both
    /// fields to the same surface, and this surface with both fields is
    /// outputted only once.
    interlaced: bool,
}

impl<T> Dpb<T>
where
    T: DecodedHandle<CodecData = PictureData<<T as DecodedHandle>::BackendHandle>>,
{
    /// Returns an iterator over the underlying H264 pictures stored in the
    /// handles.
    pub fn pictures(
        &self,
    ) -> impl Iterator<Item = Ref<'_, H264Picture<<T as DecodedHandle>::BackendHandle>>> + '_ {
        self.handles.iter().map(|h| h.picture())
    }

    /// Returns a mutable iterator over the underlying H264 pictures stored in
    /// the handles.
    pub fn pictures_mut(
        &self,
    ) -> impl Iterator<Item = RefMut<'_, H264Picture<<T as DecodedHandle>::BackendHandle>>> + '_
    {
        self.handles.iter().map(|h| h.picture_mut())
    }

    /// Get a reference to the dpb's picture handles.
    pub fn handles(&self) -> &Vec<T> {
        &self.handles
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
    pub fn find_short_term_lowest_frame_num_wrap(&self) -> Option<T> {
        let lowest = self
            .handles()
            .iter()
            .cloned()
            .filter(|h| {
                let p = h.picture();
                matches!(p.reference(), Reference::ShortTerm)
            })
            .min_by_key(|h| {
                let p = h.picture();
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
        self.handles.retain(|handle| {
            let pic = handle.picture();
            let discard = !pic.is_ref() && !pic.needed_for_output;

            if discard {
                log::debug!("Removing unused picture {:#?}", pic);
            }

            !discard
        });
    }

    /// Find a short term reference picture with the given `pic_num` value.
    pub fn find_short_term_with_pic_num(&self, pic_num: i32) -> Option<T> {
        let position = self
            .pictures()
            .position(|p| matches!(p.reference(), Reference::ShortTerm) && p.pic_num == pic_num);

        log::debug!(
            "find_short_term_with_pic_num: {}, found position {:?}",
            pic_num,
            position
        );

        Some(self.handles[position?].clone())
    }

    /// Find a long term reference picture with the given `long_term_pic_num`
    /// value.
    pub fn find_long_term_with_long_term_pic_num(&self, long_term_pic_num: i32) -> Option<T> {
        let position = self.pictures().position(|p| {
            matches!(p.reference(), Reference::LongTerm) && p.long_term_pic_num == long_term_pic_num
        });

        log::debug!(
            "find_long_term_with_long_term_pic_num: {}, found position {:?}",
            long_term_pic_num,
            position
        );

        Some(self.handles[position?].clone())
    }

    /// Store a picture in the DPB.
    pub fn store_picture(&mut self, handle: T) -> Result<()> {
        let max_pics = if self.interlaced {
            self.max_num_pics * 2
        } else {
            self.max_num_pics
        };

        if self.handles.len() >= max_pics {
            return Err(anyhow!("Can't add a picture to the DPB: DPB is full."));
        }

        let mut pic_mut = handle.picture_mut();

        // C.4.2. Decoding of gaps in frame_num and storage of "non-existing"
        // pictures
        if !pic_mut.nonexisting {
            pic_mut.needed_for_output = true;
        } else {
            pic_mut.needed_for_output = false;
        }

        if pic_mut.is_second_field() {
            let first_field_rc = pic_mut.other_field_unchecked();
            let mut first_field = first_field_rc.borrow_mut();
            drop(pic_mut);
            first_field.set_second_field_to(Rc::clone(handle.picture_container()));
            pic_mut = handle.picture_mut();
        }

        debug!(
            "Stored picture POC {:?}, field {:?}, the DPB length is {:?}",
            pic_mut.pic_order_cnt,
            pic_mut.field,
            self.handles.len() + 1
        );

        drop(pic_mut);
        self.handles.push(handle);

        Ok(())
    }

    /// Whether the DPB has an empty slot for a new picture.
    pub fn has_empty_frame_buffer(&self) -> bool {
        if !self.interlaced {
            self.handles.len() < self.max_num_pics
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
    pub fn needs_bumping(&self, to_insert: &H264Picture<T::BackendHandle>) -> bool {
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
            Some(handle) => handle.picture().pic_order_cnt,
            None => return false,
        };

        !to_insert.is_second_field_of_complementary_ref_pair()
            && to_insert.pic_order_cnt > lowest_poc
    }

    /// Find the lowest POC in the DPB that can be bumped.
    fn find_lowest_poc_for_bumping(&self) -> Option<T> {
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
            .handles
            .iter()
            .position(|handle| handle.picture().pic_order_cnt == lowest.pic_order_cnt)
            .unwrap();

        Some(self.handles[position].clone())
    }

    /// Gets the position of `needle` in the DPB, if any.
    fn get_position(&self, needle: &ContainedPicture<T::BackendHandle>) -> Option<usize> {
        self.handles.iter().position(|handle| {
            let p = handle.picture_container();
            Rc::ptr_eq(p, needle)
        })
    }

    /// Bump the dpb, returning a picture as per the bumping process described in C.4.5.3.
    /// Note that this picture will still be referenced by its pair, if any.
    pub fn bump(&mut self, flush: bool) -> Option<T> {
        let handle = self.find_lowest_poc_for_bumping()?;
        let pic_rc = handle.picture_container();
        let mut pic = pic_rc.borrow_mut();

        debug!("Bumping picture {:#?} from the dpb", pic);

        pic.needed_for_output = false;

        if !pic.is_ref() || flush {
            let index = self.get_position(pic_rc).unwrap();
            log::debug!("removed picture {:#?} from dpb", pic);
            self.handles.remove(index);
        }

        if pic.other_field().is_some() {
            let other_field_rc = pic.other_field_unchecked();
            let mut other_field = other_field_rc.borrow_mut();
            other_field.needed_for_output = false;

            if !other_field.is_ref() {
                log::debug!("other_field: removed picture {:#?} from dpb", other_field);
                let index = self.get_position(&other_field_rc).unwrap();
                self.handles.remove(index);
            }
        }

        drop(pic);
        Some(handle)
    }

    /// Drains the DPB by continuously invoking the bumping process.
    pub fn drain(&mut self) -> Vec<T> {
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

    /// Gets a Vec<ContainedPicture> of short term refs into `out`
    pub fn get_short_term_refs(&self, out: &mut Vec<T>) {
        out.extend(
            self.handles()
                .iter()
                .filter(|&handle| matches!(handle.picture().reference(), Reference::ShortTerm))
                .cloned(),
        )
    }

    /// Gets a Vec<ContainedPicture> of long term refs into `out`
    pub fn get_long_term_refs(&self, out: &mut Vec<T>) {
        out.extend(
            self.handles()
                .iter()
                .filter(|&handle| matches!(handle.picture().reference(), Reference::LongTerm))
                .cloned(),
        )
    }
}

impl<Handle> Default for Dpb<Handle> {
    fn default() -> Self {
        // See https://github.com/rust-lang/rust/issues/26925 on why this can't
        // be derived.
        Self {
            handles: Default::default(),
            max_num_pics: Default::default(),
            interlaced: Default::default(),
        }
    }
}

impl<T> std::fmt::Debug for Dpb<T>
where
    T: DecodedHandle<CodecData = PictureData<<T as DecodedHandle>::BackendHandle>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pics = self.pictures().enumerate().collect::<Vec<_>>();
        f.debug_struct("Dpb")
            .field("pictures", &pics)
            .field("max_num_pics", &self.max_num_pics)
            .field("interlaced", &self.interlaced)
            .finish()
    }
}

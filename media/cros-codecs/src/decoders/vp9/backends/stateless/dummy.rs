// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This file contains a dummy backend whose only purpose is to let the decoder
//! run so we can test it in isolation.

use std::cell::Ref;
use std::cell::RefCell;
use std::cell::RefMut;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::decoders::vp9::backends::stateless::ContainedPicture;
use crate::decoders::vp9::backends::stateless::DecodedHandle;
use crate::decoders::vp9::backends::stateless::StatelessDecoderBackend;
use crate::decoders::vp9::parser::NUM_REF_FRAMES;
use crate::decoders::vp9::picture::Picture;
use crate::decoders::DynDecodedHandle;
use crate::decoders::DynPicture;
use crate::decoders::VideoDecoderBackend;
use crate::DecodedFormat;
use crate::Resolution;

pub type AssociatedDummyHandle = <Backend as StatelessDecoderBackend>::Handle;

pub type AssociatedDummyBackendHandle = <AssociatedDummyHandle as DecodedHandle>::BackendHandle;

pub struct MappedHandle;

impl AsRef<[u8]> for MappedHandle {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

pub struct BackendHandle;

impl crate::decoders::MappableHandle for BackendHandle {
    fn map(&mut self) -> crate::decoders::Result<Box<dyn AsRef<[u8]> + '_>> {
        Ok(Box::new(MappedHandle {}))
    }

    fn read(&mut self, _: &mut [u8]) -> crate::decoders::Result<()> {
        Ok(())
    }

    fn mapped_resolution(&mut self) -> crate::decoders::Result<Resolution> {
        Ok(Resolution {
            width: 1,
            height: 1,
        })
    }
}

#[derive(Clone)]
pub struct Handle {
    handle: Rc<RefCell<Picture<BackendHandle>>>,
}

pub struct Backend;

impl DecodedHandle for Handle {
    type BackendHandle = BackendHandle;

    fn picture(&self) -> Ref<Picture<Self::BackendHandle>> {
        self.handle.borrow()
    }

    fn picture_mut(&self) -> RefMut<Picture<Self::BackendHandle>> {
        self.handle.borrow_mut()
    }

    fn picture_container(&self) -> ContainedPicture<Self::BackendHandle> {
        self.handle.clone()
    }

    fn timestamp(&self) -> u64 {
        0
    }

    fn display_resolution(&self) -> Resolution {
        Default::default()
    }

    fn display_order(&self) -> Option<u64> {
        None
    }

    fn set_display_order(&mut self, _: u64) {}
}

impl DynDecodedHandle for Handle {
    fn dyn_picture(&self) -> Ref<dyn crate::decoders::DynPicture> {
        self.picture()
    }

    fn dyn_picture_mut(&self) -> RefMut<dyn DynPicture> {
        self.picture_mut()
    }

    fn timestamp(&self) -> u64 {
        DecodedHandle::timestamp(self)
    }

    fn display_resolution(&self) -> Resolution {
        DecodedHandle::display_resolution(self)
    }

    fn display_order(&self) -> Option<u64> {
        DecodedHandle::display_order(self)
    }
}

impl VideoDecoderBackend for Backend {
    fn num_resources_total(&self) -> usize {
        1
    }

    fn num_resources_left(&self) -> usize {
        1
    }

    fn format(&self) -> Option<DecodedFormat> {
        None
    }

    fn try_format(&mut self, _: DecodedFormat) -> crate::decoders::Result<()> {
        Ok(())
    }

    fn supported_formats_for_stream(&self) -> crate::decoders::Result<HashSet<DecodedFormat>> {
        Ok(HashSet::new())
    }

    fn coded_resolution(&self) -> Option<Resolution> {
        None
    }

    fn display_resolution(&self) -> Option<Resolution> {
        None
    }
}

impl StatelessDecoderBackend for Backend {
    type Handle = Handle;

    fn new_sequence(&mut self, _: &crate::decoders::vp9::parser::Header) -> super::Result<()> {
        Ok(())
    }

    fn submit_picture(
        &mut self,
        picture: Picture<super::AsBackendHandle<Self::Handle>>,
        _: &[Option<Self::Handle>; NUM_REF_FRAMES],
        _: &dyn AsRef<[u8]>,
        _: u64,
        _: bool,
    ) -> super::Result<Self::Handle> {
        Ok(Handle {
            handle: Rc::new(RefCell::new(picture)),
        })
    }

    fn poll(&mut self, _: super::BlockingMode) -> super::Result<VecDeque<Self::Handle>> {
        Ok(VecDeque::new())
    }

    fn handle_is_ready(&self, _: &Self::Handle) -> bool {
        true
    }

    fn block_on_handle(&mut self, _: &Self::Handle) -> super::Result<()> {
        Ok(())
    }

    fn as_video_decoder_backend_mut(&mut self) -> &mut dyn VideoDecoderBackend {
        self
    }

    fn as_video_decoder_backend(&self) -> &dyn VideoDecoderBackend {
        self
    }
}

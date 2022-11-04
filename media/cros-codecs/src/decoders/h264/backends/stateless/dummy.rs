// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This file contains a dummy backend whose only purpose is to let the decoder
//! run so we can test it in isolation.

use std::cell::RefCell;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::decoders::h264::backends::stateless::AsBackendHandle;
use crate::decoders::h264::backends::stateless::BlockingMode;
use crate::decoders::h264::backends::stateless::ContainedPicture;
use crate::decoders::h264::backends::stateless::DecodedHandle;
use crate::decoders::h264::backends::stateless::Result as StatelessBackendResult;
use crate::decoders::h264::backends::stateless::StatelessDecoderBackend;
use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::parser::Pps;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::h264::picture::PictureData;
use crate::decoders::VideoDecoderBackend;
use crate::DecodedFormat;
use crate::Resolution;

pub type AssociatedDummyHandle = <Backend as StatelessDecoderBackend>::Handle;

pub type AssociatedDummyBackendHandle = <AssociatedDummyHandle as DecodedHandle>::BackendHandle;

pub struct BackendHandle;

impl crate::decoders::MappableHandle for BackendHandle {
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
    handle: Rc<RefCell<H264Picture<BackendHandle>>>,
}

pub struct Backend;

impl DecodedHandle for Handle {
    type CodecData = PictureData<Self::BackendHandle>;
    type BackendHandle = BackendHandle;

    fn picture_container(&self) -> &ContainedPicture<Self::BackendHandle> {
        &self.handle
    }

    fn display_resolution(&self) -> Resolution {
        self.picture().display_resolution
    }

    fn display_order(&self) -> Option<u64> {
        None
    }

    fn set_display_order(&mut self, _: u64) {}
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

    fn new_sequence(&mut self, _: &Sps, _: usize) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn handle_picture(
        &mut self,
        _: &H264Picture<AssociatedDummyBackendHandle>,
        _: u64,
        _: &Sps,
        _: &Pps,
        _: &Dpb<Self::Handle>,
        _: &Slice<&dyn AsRef<[u8]>>,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn new_field_picture(
        &mut self,
        _: &H264Picture<AssociatedDummyBackendHandle>,
        _: u64,
        _: &Self::Handle,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn decode_slice(
        &mut self,
        _: &Slice<&dyn AsRef<[u8]>>,
        _: &Sps,
        _: &Pps,
        _: &Dpb<Self::Handle>,
        _: &[Self::Handle],
        _: &[Self::Handle],
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn submit_picture(
        &mut self,
        picture: H264Picture<AsBackendHandle<Self::Handle>>,
        _: bool,
    ) -> StatelessBackendResult<Self::Handle> {
        Ok(Handle {
            handle: Rc::new(RefCell::new(picture)),
        })
    }

    fn poll(&mut self, _: BlockingMode) -> StatelessBackendResult<VecDeque<Self::Handle>> {
        Ok(VecDeque::new())
    }

    fn new_handle(
        &mut self,
        picture: ContainedPicture<AsBackendHandle<Self::Handle>>,
    ) -> StatelessBackendResult<Self::Handle> {
        Ok(Handle { handle: picture })
    }

    fn new_split_picture(
        &mut self,
        _: ContainedPicture<AsBackendHandle<Self::Handle>>,
        _: ContainedPicture<AsBackendHandle<Self::Handle>>,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn new_picture(
        &mut self,
        _: &H264Picture<AsBackendHandle<Self::Handle>>,
        _: u64,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn handle_is_ready(&self, _: &Self::Handle) -> bool {
        true
    }

    fn as_video_decoder_backend_mut(&mut self) -> &mut dyn VideoDecoderBackend {
        self
    }

    fn as_video_decoder_backend(&self) -> &dyn VideoDecoderBackend {
        self
    }

    fn block_on_handle(&mut self, _: &Self::Handle) -> StatelessBackendResult<()> {
        Ok(())
    }
}

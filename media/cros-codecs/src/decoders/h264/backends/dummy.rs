// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This file contains a dummy backend whose only purpose is to let the decoder
//! run so we can test it in isolation.

use std::cell::RefCell;
use std::rc::Rc;

use crate::decoders::h264::backends::AsBackendHandle;
use crate::decoders::h264::backends::ContainedPicture;
use crate::decoders::h264::backends::Result as StatelessBackendResult;
use crate::decoders::h264::backends::StatelessDecoderBackend;
use crate::decoders::h264::decoder::Decoder;
use crate::decoders::h264::dpb::Dpb;
use crate::decoders::h264::parser::Pps;
use crate::decoders::h264::parser::Slice;
use crate::decoders::h264::parser::Sps;
use crate::decoders::h264::picture::H264Picture;
use crate::decoders::BlockingMode;
use crate::utils::dummy::*;

impl StatelessDecoderBackend for Backend<H264Picture<BackendHandle>> {
    fn new_sequence(&mut self, _: &Sps) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn handle_picture(
        &mut self,
        _: &H264Picture<BackendHandle>,
        _: u64,
        _: &Sps,
        _: &Pps,
        _: &Dpb<Self::Handle>,
        _: &Slice<&[u8]>,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn new_field_picture(
        &mut self,
        _: &H264Picture<BackendHandle>,
        _: u64,
        _: &Self::Handle,
    ) -> StatelessBackendResult<()> {
        Ok(())
    }

    fn decode_slice(
        &mut self,
        _: &Slice<&[u8]>,
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

    #[cfg(test)]
    fn get_test_params(&self) -> &dyn std::any::Any {
        // There are no test parameters for the dummy backend.
        unimplemented!()
    }
}

impl Decoder<Handle<H264Picture<BackendHandle>>> {
    // Creates a new instance of the decoder using the dummy backend.
    pub fn new_dummy(blocking_mode: BlockingMode) -> anyhow::Result<Self> {
        Self::new(Box::new(Backend::new()), blocking_mode)
    }
}

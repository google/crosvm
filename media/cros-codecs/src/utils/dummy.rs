// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This file contains a dummy backend whose only purpose is to let the decoder
//! run so we can test it in isolation.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::decoders::BlockingMode;
use crate::decoders::DecodedHandle;
use crate::decoders::DynHandle;
use crate::decoders::MappableHandle;
use crate::decoders::Result;
use crate::decoders::StatelessBackendResult;
use crate::decoders::VideoDecoderBackend;
use crate::DecodedFormat;
use crate::Resolution;

pub struct BackendHandle;

impl MappableHandle for BackendHandle {
    fn read(&mut self, _: &mut [u8]) -> Result<()> {
        Ok(())
    }

    fn image_size(&mut self) -> usize {
        1
    }
}

impl DynHandle for BackendHandle {
    fn dyn_mappable_handle_mut<'a>(&'a mut self) -> Box<dyn MappableHandle + 'a> {
        Box::new(BackendHandle)
    }
}

pub struct Handle {
    pub handle: Rc<RefCell<BackendHandle>>,
}

impl Clone for Handle {
    fn clone(&self) -> Self {
        Self {
            handle: Rc::clone(&self.handle),
        }
    }
}

impl DecodedHandle for Handle {
    type BackendHandle = BackendHandle;

    fn handle_rc(&self) -> &Rc<RefCell<Self::BackendHandle>> {
        &self.handle
    }

    fn display_resolution(&self) -> Resolution {
        Default::default()
    }

    fn display_order(&self) -> Option<u64> {
        None
    }

    fn set_display_order(&mut self, _: u64) {}

    fn timestamp(&self) -> u64 {
        0
    }
}

/// Dummy backend that can be used for any codec.
pub(crate) struct Backend;

impl Backend {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl VideoDecoderBackend for Backend
where
    Handle: DecodedHandle,
{
    type Handle = Handle;

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

    fn coded_resolution(&self) -> Option<Resolution> {
        None
    }

    fn display_resolution(&self) -> Option<Resolution> {
        None
    }

    fn poll(&mut self, _: BlockingMode) -> crate::decoders::Result<VecDeque<Self::Handle>> {
        Ok(VecDeque::new())
    }

    fn handle_is_ready(&self, _: &Self::Handle) -> bool {
        true
    }

    fn block_on_handle(&mut self, _: &Self::Handle) -> StatelessBackendResult<()> {
        Ok(())
    }
}

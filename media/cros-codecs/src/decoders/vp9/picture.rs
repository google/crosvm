// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::decoders::vp9::parser::Header;
use crate::decoders::FrameInfo;
use crate::decoders::Picture;
use crate::Resolution;

pub type Vp9Picture<T> = Picture<Header, T>;

impl<BackendHandle> Picture<Header, BackendHandle> {
    pub fn new_vp9(header: Header, backend_handle: Option<BackendHandle>, timestamp: u64) -> Self {
        Self {
            data: header,
            backend_handle,
            timestamp,
        }
    }
}

impl FrameInfo for Header {
    fn display_resolution(&self) -> crate::Resolution {
        Resolution {
            width: self.width() as u32,
            height: self.height() as u32,
        }
    }
}

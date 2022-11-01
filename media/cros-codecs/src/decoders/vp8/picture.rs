// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::decoders::vp8::parser::Header;
use crate::decoders::Picture;

pub type Vp8Picture<T> = Picture<Header, T>;

impl<BackendHandle> Picture<Header, BackendHandle> {
    pub fn new_vp8(header: Header, backend_handle: Option<BackendHandle>, timestamp: u64) -> Self {
        Self {
            data: header,
            backend_handle,
            timestamp,
        }
    }
}

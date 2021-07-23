// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Cursor;

use crate::protocol::{Tframe, WireFormat};

pub fn tframe_decode(bytes: &[u8]) {
    let mut cursor = Cursor::new(bytes);

    while Tframe::decode(&mut cursor).is_ok() {}
}

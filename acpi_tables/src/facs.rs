// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[repr(packed)]
#[derive(Clone, Copy, Default, FromBytes, AsBytes)]
pub struct FACS {
    pub signature: [u8; 4],
    pub length: u32,
    pub hardware_signature: u32,
    pub waking: u32,
    pub lock: u32,
    pub flags: u32,
    pub x_waking: u64,
    pub version: u8,
    pub _reserved1: [u8; 3],
    pub ospm_flags: u32,
    pub _reserved2: [u8; 24],
}

impl FACS {
    pub fn new() -> Self {
        FACS {
            signature: *b"FACS",
            length: std::mem::size_of::<FACS>() as u32,
            hardware_signature: 0,
            waking: 0,
            lock: 0,
            flags: 0,
            x_waking: 0,
            version: 1,
            _reserved1: [0; 3],
            ospm_flags: 0,
            _reserved2: [0; 24],
        }
    }

    pub fn len() -> usize {
        std::mem::size_of::<FACS>()
    }
}

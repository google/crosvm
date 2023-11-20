// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod tap;
use base::FileReadWriteVolatile;
pub use tap::Tap;

use crate::TapTCommon;

/// Linux-specific TAP functions
pub trait TapTLinux {
    /// Set the size of the vnet hdr.
    fn set_vnet_hdr_size(&self, size: usize) -> Result<(), crate::Error>;

    /// Get the interface flags
    fn if_flags(&self) -> u32;
}

// TODO(b/159159958) implement FileReadWriteVolatile for slirp
pub trait TapT: FileReadWriteVolatile + TapTCommon + TapTLinux {}

pub mod fakes {
    pub use super::tap::fakes::FakeTap;
}

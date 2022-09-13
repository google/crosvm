// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod tap;
use base::FileReadWriteVolatile;
pub use tap::Tap;

use crate::TapTCommon;

// TODO(b/159159958) implement FileReadWriteVolatile for slirp
pub trait TapT: FileReadWriteVolatile + TapTCommon {}

pub mod fakes {
    pub use super::tap::fakes::FakeTap;
}

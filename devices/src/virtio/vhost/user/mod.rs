// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod device;
pub mod vmm;

pub use self::device::*;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod proxy;
        pub use self::proxy::*;
    } else if #[cfg(windows)] {}
}

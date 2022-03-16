// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub(crate) use unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub(crate) use windows::*;
    }
}

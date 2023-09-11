// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        #[cfg(test)]
        pub use unix::test_helpers;
    } else if #[cfg(windows)] {
        pub mod windows;
        #[cfg(test)]
        pub use windows::test_helpers;
    }
}

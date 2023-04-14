// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(feature = "trace_marker")] {
        /// A wrapper around trace_marker tracing features
        pub mod trace_marker;
        use trace_marker as platform;

        pub use trace_marker::*;
    } else if #[cfg(feature = "perfetto")] {
        pub mod perfetto;
        use self::perfetto as platform;
        pub use platform::*;
    }
    else {
        /// A crate that provides noop tracing.
        pub mod noop;
        use noop as platform;
    }
}

pub use platform::init;

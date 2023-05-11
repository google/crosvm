// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(feature = "trace_marker")] {
        /// A wrapper around trace_marker tracing features
        mod trace_marker;
        pub use trace_marker::*;
    } else if #[cfg(feature = "perfetto")] {
        mod perfetto;
        pub use perfetto::*;
    }
    else {
        /// A crate that provides noop tracing.
        mod noop;
        pub use noop::*;
    }
}

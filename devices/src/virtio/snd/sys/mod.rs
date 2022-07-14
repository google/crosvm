// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        use unix as platform;
        #[cfg(feature = "audio_cras")]
        pub(crate) use platform::create_cras_stream_source_generators;
    } else if #[cfg(windows)] {
        mod windows;
        use windows as platform;
    }
}

pub use platform::StreamSourceBackend;
pub(crate) use platform::{create_stream_source_generators, parse_args, set_audio_thread_priority};

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use linux as platform;
    } else if #[cfg(windows)] {
        pub(crate) mod windows;
        use windows as platform;
    }
}

pub(crate) use platform::create_stream_source_generators;
pub(crate) use platform::set_audio_thread_priority;
pub use platform::StreamSourceBackend;
pub(crate) use platform::SysAsyncStreamObjects;
pub(crate) use platform::SysAudioStreamSource;
pub(crate) use platform::SysAudioStreamSourceGenerator;
pub(crate) use platform::SysDirectionOutput;

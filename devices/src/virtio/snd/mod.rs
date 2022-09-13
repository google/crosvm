// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod common;
pub mod constants;
pub mod layout;
pub mod parameters;
pub mod sys;

#[cfg(feature = "audio")]
pub mod common_backend;
#[cfg(feature = "audio")]
pub mod null_backend;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod vios_backend;

        pub use vios_backend::new_sound;
        pub use vios_backend::SoundError;
    }
}

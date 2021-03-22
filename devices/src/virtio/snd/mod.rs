// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod common;
pub mod constants;
pub mod layout;

#[cfg(feature = "audio_cras")]
pub mod cras_backend;

pub mod vios_backend;

pub use vios_backend::new_sound;
pub use vios_backend::SoundError;

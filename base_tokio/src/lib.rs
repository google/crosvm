// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Tokio versions of type's defined in crosvm's `base` crate.

mod sys {
    cfg_if::cfg_if! {
        if #[cfg(any(target_os = "android", target_os = "linux"))] {
            pub mod linux;
            pub use linux::*;
        } else if #[cfg(windows)] {
            pub mod windows;
            pub use windows::*;
        }
    }
}

mod event;
mod tube;

pub use sys::event::EventTokio;
pub use sys::tube::TubeTokio;

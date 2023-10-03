// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub mod linux;
        pub use linux as platform;
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows as platform;
    }
}

pub use platform::async_types;
pub use platform::event;
pub use platform::executor::Executor;
pub use platform::executor::ExecutorKind;
pub use platform::executor::SetDefaultExecutorKindError;
pub use platform::executor::TaskHandle;

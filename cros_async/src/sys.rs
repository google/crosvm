// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        pub use unix as platform;
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
pub use platform::run_one;

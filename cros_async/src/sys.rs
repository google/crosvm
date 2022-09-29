// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        pub use unix::{async_types, event, executor::Executor, run_one};
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows::{async_types, event, executor::Executor, run_one};
    }
}

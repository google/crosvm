// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        use unix as platform;
        pub(crate) use unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        use windows as platform;
        pub(crate) use windows::*;
    }
}

pub(crate) use platform::get_acpi_event_sock;

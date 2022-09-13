// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Do nothing on unix as the library is windows only.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    #[cfg(target_env = "msvc")]
    windows::build!(Windows::Win32::Globalization::ImmDisableIME)
}

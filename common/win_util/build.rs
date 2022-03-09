// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Do nothing on unix as the library is windows only.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    windows::build!(Windows::Win32::Globalization::ImmDisableIME)
}

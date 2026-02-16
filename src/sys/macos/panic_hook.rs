// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub(crate) fn set_panic_hook() {
    // On macOS, set up a default panic hook that prints to stderr
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("crosvm panic: {}", panic_info);
    }));
}

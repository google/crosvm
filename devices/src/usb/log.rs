// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(jkwang) remove this macro once we have a proper tracing system.
#[macro_export]
macro_rules! usb_debug {
    ($($args:tt)+) => {
        // Set true to enable logging.
        if false {
            base::debug!($($args)*);
        }
    };
}

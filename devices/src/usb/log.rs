// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(jkwang) remove this macro once we have a proper tracing system.
#[macro_export]
macro_rules! usb_debug {
    ($($args:tt)+) => {
        // Set true to enable logging.
        if false {
            sys_util::debug!($($args)*);
        }
    };
}

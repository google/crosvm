// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[macro_export]
macro_rules! usb_trace {
    ($($args:tt)+) => {
        cros_tracing::trace_simple_print!(USB, "usb host device: {}", std::format!($($args)*))
    };
}

#[macro_export]
macro_rules! xhci_trace {
    ($($args:tt)+) => {
        cros_tracing::trace_simple_print!(USB, "xhci: {}", std::format!($($args)*))
    };
}

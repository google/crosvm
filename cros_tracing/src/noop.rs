// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Empty macros for when the tracing feature isn't used.
#[macro_export]
macro_rules! trace_event {
    ($category:ident, $name:expr) => {
        None as Option<bool>
    };
}

#[macro_export]
macro_rules! trace_event_begin {
    ($category:ident, $name:expr) => {};
}

#[macro_export]
macro_rules! trace_event_end {
    ($category:ident) => {};
}

#[macro_export]
macro_rules! trace_simple_print {
    ($($t:tt)*) => {};
}

#[macro_export]
macro_rules! push_descriptors {
    ($fd_vec:expr) => {};
}

pub fn init() {}

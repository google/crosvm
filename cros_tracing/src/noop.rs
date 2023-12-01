// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Empty macros for when the tracing feature isn't used.
#[macro_export]
macro_rules! trace_event {
    ($category:ident, $name:expr $(,$t:expr)*) => {{
        // Real backends will return an Option type.
        None as Option<bool>
    }};
}

// This is NOT part of the public cros_tracing interface. Some backends
// need to expose it since macros calling macros requires the inner macros
// to be public.
#[macro_export]
macro_rules! trace_event_begin {
    ($category:ident, $name:literal $(,$t:expr)*) => {};
}

// Similarly, this is not public.
#[macro_export]
macro_rules! trace_event_end {
    ($category:ident $(,$t:expr)*) => {};
}

#[macro_export]
macro_rules! trace_simple_print {
    ($($t:tt)+) => {};
}

#[macro_export]
macro_rules! push_descriptors {
    ($fd_vec:expr) => {};
}

pub fn init() {}

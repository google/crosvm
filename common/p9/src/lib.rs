// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

extern crate libc;

#[macro_use]
extern crate wire_format_derive;

mod protocol;
mod server;

#[cfg(fuzzing)]
pub mod fuzzing;

pub use server::*;

#[macro_export]
macro_rules! syscall {
    ($e:expr) => {{
        let res = $e;
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

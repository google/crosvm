// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

#[allow(clippy::all)]
pub mod bindings;
pub use bindings::*;

pub mod msrs;
pub use msrs::*;

pub mod cpuid;
pub use cpuid::*;

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::*;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod posix;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use posix::*;

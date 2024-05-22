// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod config;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod fork;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod helpers;

pub use crate::config::JailConfig;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::fork::fork_process;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::helpers::*;

// TODO(b/268407006): We define Minijail as an empty struct as a stub for minijail::Minijail on
// Windows because the concept of jailing is baked into a bunch of places where it isn't easy to
// compile it out. In the long term, this should go away.
#[cfg(windows)]
pub struct FakeMinijailStub {}

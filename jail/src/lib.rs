// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod config;
#[cfg(unix)]
mod helpers;

pub use crate::config::JailConfig;
#[cfg(unix)]
pub use crate::helpers::*;

// TODO(b/268407006): We define Minijail as an empty struct as a stub for minijail::Minijail on
// Windows because the concept of jailing is baked into a bunch of places where it isn't easy to
// compile it out. In the long term, this should go away.
#[cfg(windows)]
pub struct FakeMinijailStub {}

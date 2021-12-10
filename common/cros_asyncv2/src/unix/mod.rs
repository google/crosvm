// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod descriptor;
mod event;
mod file;
mod io_driver;
mod seqpacket;

pub use descriptor::*;
pub use event::*;
pub use file::*;
pub use seqpacket::*;

use crate::executor;

#[inline]
pub(crate) fn platform_state() -> anyhow::Result<impl executor::PlatformState> {
    io_driver::platform_state()
}

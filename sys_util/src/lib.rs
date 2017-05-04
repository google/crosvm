// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate libc;

mod mmap;
mod eventfd;
mod errno;
mod struct_util;

pub use mmap::*;
pub use eventfd::*;
pub use errno::{Error, Result};
use errno::errno_result;
pub use struct_util::*;

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

extern crate data_model;
extern crate libc;

#[macro_use]
pub mod handle_eintr;
mod mmap;
mod eventfd;
mod errno;
mod guest_address;
mod guest_memory;
mod poll;
mod struct_util;
mod tempdir;
mod terminal;
mod signal;

pub use mmap::*;
pub use eventfd::*;
pub use errno::{Error, Result};
use errno::errno_result;
pub use guest_address::*;
pub use guest_memory::*;
pub use poll::*;
pub use struct_util::*;
pub use tempdir::*;
pub use terminal::*;
pub use signal::*;

pub use guest_memory::Error as GuestMemoryError;

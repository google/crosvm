// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the `libvda` video decoder and encoder libraries.

#![cfg(unix)]

pub mod decode;
pub mod encode;

mod bindings;
mod error;
mod format;

pub use error::*;
pub use format::*;
